// 云伴登录：账号密码 + 图形验证码（手动输入）+ 短信验证码（如果上游要求），
// 在本地页上完成，每次 authorize 起一个独立的本地服务。
// 图形验证码不做自动识别；密码只在内存里使用，不写文件、不回显。
//
// 登录结果的形状由宿主定义：成功 {type:"success", …凭据}，失败 {type:"failed", error}。
// 返回值的 type 不是 "success" 时宿主按失败处理、不保存任何内容。
//
// 约定：
// - 页面令牌只经 URL fragment 交给页面脚本（不进 HTML、Referer、日志），页面存入
//   sessionStorage 以便刷新
// - 已知秘密（密码、短信 ticket）在写入本地页或日志前按原值擦除
// - 登录结束后（settled），迟到的响应不再改变状态
// - 宿主取消或超时会中止 callback 的 signal，整个登录随之失败并关闭本地页
// - 页面上选的登录方式在重绘后保持；验证码失败次数与重发次数按新的短信挑战重置
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startPage, pageResponse, readBody, parseParams, randomUUID, safeAccountKey } from "../common/page.mjs";
import { log, isNetworkError, networkErrorMessage, redact, scrubValues } from "../common/http.mjs";
import { postAnon, postSigned, parseUpstreamError } from "./upstream.mjs";
import { mergeMe, accountIdOf, nextExpiry } from "./session.mjs";

// 出现这些错误码时本次登录失败，不重试。
const IAM_TERMINAL_CODES = ["account_locked", "password_expired", "sms_unavailable", "account_disabled", "upstream_unreachable", "not_found"];
const CAPTCHA_MAX_FAILS = 3;
const SMS_MAX_RESENDS = 3;
const TTL_MS = 10 * 60 * 1000; // 整个登录流程的上限
const DEVICE_RE = /^[0-9a-f]{32}$/;

// 安装级 deviceId（uuid v4 去掉连字符）：同一台机器上所有云伴账号共用，不轮换。
// 登录成功后它随凭据保存；但宿主给插件的 client.auth 只有 set / remove，读不到旧记录，
// 所以同一台机器的值存在 os.tmpdir() 的文件里。
// 文件内容不完全可信：只接受 32 位 hex（它会进入登录请求体）。
const DEFAULT_DEVICE_FILE = join(tmpdir(), "magpie-omni2api-yunban-device.json");

function deviceIdForInstall(file) {
  try {
    const v = JSON.parse(readFileSync(file, "utf8"));
    if (typeof v?.deviceId === "string" && DEVICE_RE.test(v.deviceId)) return v.deviceId;
  } catch {}
  const id = randomUUID().replace(/-/g, "");
  try {
    // 先写临时文件再换名，并设私有权限：不跟随固定路径上可能存在的符号链接
    const tmp = `${file}.${process.pid}.${randomUUID()}.tmp`;
    writeFileSync(tmp, JSON.stringify({ deviceId: id }), { mode: 0o600 });
    renameSync(tmp, file);
  } catch {}
  return id;
}

// 登录响应解析：
// 1. challenge 为真值（null 为假）→ 需要短信验证，ticket 必须非空
// 2. 否则 token 与 sessionKey 必须都是非空字符串
export function parseLoginPayload(v) {
  const ch = v?.challenge; // null / undefined / "" / 0 视为没有挑战
  if (ch) {
    const ticket = typeof ch.ticket === "string" ? ch.ticket : "";
    if (!ticket) return { fatal: "登录响应格式变化：挑战缺少 ticket" };
    const mobile = typeof ch?.params?.mobile === "string" ? ch.params.mobile : "";
    return { sms: { ticket, mobile } };
  }
  const token = typeof v?.token === "string" ? v.token : "";
  const sessionKey = typeof v?.sessionKey === "string" ? v.sessionKey : "";
  if (!token || !sessionKey) return { fatal: "上游响应格式变化：登录响应缺少 token/sessionKey" };
  return { session: { token, sessionKey, expiresAt: typeof v?.expiresAt === "string" ? v.expiresAt : "" } };
}

// 按错误码分类登录失败。
export function classifyLoginError(code, message) {
  if (code === "captcha_invalid" || code === "captcha_expired" || code === "captcha_error" || message.includes("验证码")) {
    return { retryCaptcha: message };
  }
  if (code === "invalid_credentials") return { fatal: `账号或密码不对（${message}）` };
  if (IAM_TERMINAL_CODES.includes(code)) {
    const unreachable = code === "upstream_unreachable";
    return {
      fatal: unreachable ? `上游统一认证暂不可达（${message}）` : `账号状态异常或挑战已终止（${code}）：${message}`,
    };
  }
  return { fatal: `登录失败 [${code}]: ${message}` };
}

// 登录接口共用的请求与解析；path 和 body 由调用方给。
async function postLogin(base, path, body, state) {
  let r;
  try {
    r = await postAnon(base, path, body, { signal: state.signal, timeoutMs: 30000 });
  } catch (e) {
    if (isNetworkError(e, state.signal)) return { fatal: networkErrorMessage(base, e) };
    throw e;
  }
  if (r.ok) {
    if (r.json === undefined || typeof r.json !== "object") return { fatal: "上游响应格式变化：登录响应不是 JSON" };
    return parseLoginPayload(r.json);
  }
  const [code, message] = parseUpstreamError(r.status, r.text);
  // challenge_invalid 与 signature_invalid 都表示短信挑战已作废：
  // 回到验证码表单重新发起，不当作可重试的错误。
  if (path === "/auth/iam/challenge" && (code === "challenge_invalid" || code === "signature_invalid")) return { restart: message };
  return classifyLoginError(code, message);
}

// 重发短信码。
async function resendSms(base, state) {
  let r;
  try {
    r = await postAnon(base, "/auth/iam/resend", { ticket: state.ticket }, { signal: state.signal, timeoutMs: 30000 });
  } catch (e) {
    if (isNetworkError(e, state.signal)) return { error: networkErrorMessage(base, e) };
    throw e;
  }
  if (r.ok) return { note: "已重发，请注意查收" };
  const [code, message] = parseUpstreamError(r.status, r.text);
  return { error: `重发失败 [${code}] ${message}` };
}

// 登录完成：构建凭据；调用 /me 取身份并更新轮换后的令牌（失败不影响登录）。
async function finalize(base, state, session) {
  let auth = {
    refresh: session.sessionKey, // 上游没有 refresh token，续期靠调用 /me
    access: session.token,
    expires: nextExpiry(),
    accountId: state.username,
    token: session.token,
    sessionKey: session.sessionKey,
    expiresAt: session.expiresAt,
    deviceId: state.deviceId,
    loginMode: state.mode,
    username: state.username,
  };
  try {
    const me = await postSigned(base, session.token, session.sessionKey, "/me", null, { timeoutMs: 15000, signal: state.signal });
    if (me.ok && me.json && typeof me.json === "object") {
      auth = mergeMe(auth, me.json);
      auth.accountId = accountIdOf(auth) || state.username;
    }
  } catch {}
  return auth;
}

// ---------------- 本地页 ----------------

// 页面脚本：只负责渲染与提交。账号、密码是否已在服务端由 need* 字段告诉页面，
// 服务端已有的值不回显（密码不进 HTML）。接口请求都带 x-login-token：页面令牌只
// 经 URL fragment 交给页面（# 后面的部分不发给服务端、不进 Referer），脚本读到后
// 存入 sessionStorage 并从地址栏移除，其它网页拿不到它。
const PAGE_JS = `
const raw = ((location.hash || "").match(/[#&]t=([^&]*)/) || [])[1];
const TOKEN = raw ? decodeURIComponent(raw) : (sessionStorage.getItem("magpie-omni2api-page-token") || "");
if (raw) { try { sessionStorage.setItem("magpie-omni2api-page-token", TOKEN); } catch (e) {} history.replaceState(null, "", location.pathname + location.search); }
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[<>&"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" })[c]);
let captchaId = "", stage = null; // stage：页面上当前显示的阶段
const typed = { username: "", password: "" };
const err = (m) => { const e = $("msg"); if (e) e.textContent = m || ""; };
function view(title, body) { document.title = title; document.querySelector("main").innerHTML = "<h1>" + esc(title) + "</h1>" + body; }
async function api(path, body) {
  const get = body === undefined;
  try {
    const r = await fetch(path, { method: get ? "GET" : "POST", headers: Object.assign({ "x-login-token": TOKEN }, get ? {} : { "content-type": "application/json" }), body: get ? undefined : JSON.stringify(body) });
    try { return await r.json(); } catch (e) { return { error: "本地页请求失败（HTTP " + r.status + "）" }; }
  } catch (e) { return { error: "本地页连接失败，请刷新重试" }; }
}
async function loadCaptcha() {
  $("img").alt = "验证码加载中";
  const v = await api("/captcha");
  if (v.captchaId) { captchaId = v.captchaId; $("img").src = v.image; $("img").alt = "验证码"; }
  else { $("img").alt = "验证码获取失败"; err(v.error || "验证码获取失败"); }
}
function captchaView(s) {
  let h = "";
  if (s.needMode) h += '<label>登录方式</label><select id="mode"><option value="local"' + (s.mode === "sso" ? "" : " selected") + '>账号密码</option><option value="sso"' + (s.mode === "sso" ? " selected" : "") + '>企业 SSO（统一认证，可能需要短信验证码）</option></select>';
  if (s.needUser) h += '<label>账号</label><input id="u" autocomplete="username" value="' + esc(typed.username) + '">';
  if (s.needPass) h += '<label>密码（只在本次登录使用，不会保存）</label><input id="p" type="password" autocomplete="current-password" value="' + esc(typed.password) + '">';
  h += '<label>图形验证码</label><div class="row"><img class="captcha" id="img" alt="验证码"><button id="re" type="button" class="alt" style="margin-top:0">换一张</button></div>' +
    '<label>验证码</label><input id="c" autocomplete="off"><button id="go">登录</button><p class="err" id="msg"></p>';
  view("云伴登录", h);
  if (s.error) err(s.error);
  $("re").onclick = loadCaptcha;
  $("go").onclick = async () => {
    $("go").disabled = true; err("");
    try {
      if ($("u")) typed.username = $("u").value.trim();
      if ($("p")) typed.password = $("p").value;
      const body = { captchaId, captchaCode: $("c").value.trim() };
      if ($("mode")) body.loginMode = $("mode").value;
      if (typed.username) body.username = typed.username;
      if (typed.password) body.password = typed.password;
      await after(await api("/submit", body));
    } finally { const go = $("go"); if (go) go.disabled = false; }
  };
  loadCaptcha();
}
function smsView(s) {
  view("短信验证码", "<p>" + (s.mobile ? "短信验证码已发送至 " + esc(s.mobile) + "。" : "短信验证码已发送。") + "</p>" +
    '<label>短信验证码</label><input id="code" autocomplete="one-time-code">' +
    '<div class="row"><button id="ok">提交</button><button id="rs" type="button" class="alt">重发</button></div><p class="err" id="msg"></p>');
  if (s.error) err(s.error);
  $("ok").onclick = async () => {
    $("ok").disabled = true; err("");
    try { await after(await api("/sms", { code: $("code").value.trim() })); }
    finally { const ok = $("ok"); if (ok) ok.disabled = false; }
  };
  $("rs").onclick = async () => {
    const v = await api("/resend", {});
    err(v.error || v.note || "已重发");
    if (v.limit) $("rs").disabled = true;
  };
}
// after 按服务端回的阶段切换视图：阶段没变只显示原因，变了才重画。
async function after(v) {
  const prev = stage;
  stage = v.stage || prev;
  if (v.needPass === false) typed.password = ""; // 服务端已有密码，后续请求不再带
  if (v.stage === "done") return view("登录完成", '<p class="ok">登录完成，可关闭此页。</p>');
  if (v.stage === "failed") return view("登录失败", '<p class="err">' + esc(v.error || "请重新发起登录") + "</p>");
  if (stage === "sms") {
    if (prev === "sms") return err(v.error || "");
    return smsView(v);
  }
  if (prev === "captcha") { err(v.error || ""); return loadCaptcha(); }
  return captchaView(v);
}
(async () => {
  const s = await api("/state");
  if (!s.stage) return view("登录失败", '<p class="err">' + esc(s.error || "页面已失效") + "</p>");
  stage = s.stage;
  if (s.stage === "done" || s.stage === "failed") return after(s);
  if (s.stage === "sms") return smsView(s);
  captchaView(s);
})();
`;

export async function beginLogin(inputs, { input, client, base, providerId, signal, logFn, deviceFile }) {
  const warn = logFn ?? ((level, msg, secrets) => log(client, level, msg, secrets));
  const pageToken = randomUUID();
  const chosenMode = inputs?.loginMode === "sso" ? "sso" : inputs?.loginMode === "local" ? "local" : "";
  // 本次登录的生命周期信号：authorize 的 signal 或 callback 的 signal 中止时，
  // 关闭本地页并取消进行中的上游请求。
  const life = new AbortController();
  const lifeSignal = signal ? AbortSignal.any([signal, life.signal]) : life.signal;
  const state = {
    // authorize 时记录账号键，callback 完成时校验
    accountKey: safeAccountKey(input, providerId),
    mode: chosenMode || "local",
    modeChosen: !!chosenMode, // 宿主没问登录方式时，页面上让用户选
    username: String(inputs?.username ?? "").trim(),
    password: String(inputs?.password ?? ""), // password 不 trim
    deviceId: deviceIdForInstall(deviceFile ?? DEFAULT_DEVICE_FILE),
    captchaFails: 0,
    smsResends: 0,
    smsResendLimit: false,
    stage: "captcha", // captcha | sms | done | failed
    ticket: "",
    mobile: "",
    error: "",
    signal: lifeSignal,
  };

  let settle;
  const done = new Promise((resolve) => (settle = resolve));
  done.catch(() => {});
  let settled = false;
  let ttlTimer = null;
  // 只认第一次：重复提交，或超时与完成同时发生时，后续调用不再生效
  const fail = (message, secrets = []) => {
    if (settled) return;
    settled = true;
    // 密码/短信 ticket 会在上游回显里出现：进 state.error 之前先按值擦掉
    const clean = scrubValues(redact(message), [...secrets, state.password, state.ticket]);
    state.stage = "failed";
    state.error = clean;
    state.password = ""; // 用完即弃
    state.ticket = "";
    state.mobile = "";
    clearTimeout(ttlTimer);
    settle({ type: "failed", error: clean });
  };
  const succeed = (auth) => {
    if (settled) return;
    settled = true;
    state.stage = "done";
    state.password = ""; // 用完即弃
    state.ticket = "";
    state.mobile = "";
    clearTimeout(ttlTimer);
    settle({ type: "success", ...auth });
  };
  signal?.addEventListener("abort", () => fail("登录已取消"), { once: true });
  ttlTimer = setTimeout(() => fail("登录已超时，请重新发起"), TTL_MS);
  ttlTimer.unref?.();

  const json = (v, status = 200) =>
    new Response(JSON.stringify(v), {
      status,
      headers: { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff" },
    });
  // 每个非终态响应都带上页面要知道的「还缺什么」；错误文本先擦掉已知秘密
  const reply = (v) => {
    const out = { needMode: !state.modeChosen, needUser: !state.username, needPass: !state.password, mode: state.mode, ...v };
    if (out.error) out.error = scrubValues(redact(out.error), [state.password, state.ticket]);
    return json(out);
  };

  // 提交串行化：并发提交时只处理一个，后到的响应不会覆盖已完成的状态
  let busy = false;
  const withBusy = async (fn) => {
    if (busy) return reply({ stage: state.stage, error: "正在处理上一步，请稍候" });
    busy = true;
    try {
      return await fn();
    } finally {
      busy = false;
    }
  };

  // 登录尝试的共同收尾：会话 → 凭据；短信挑战 → sms；作废 → 回验证码；其余按类处理
  const settleAttempt = async (out, { fromSms = false } = {}) => {
    if (settled) return reply({ stage: state.stage, error: state.error });
    if (out.session) {
      const auth = await finalize(base, state, out.session);
      if (settled) return reply({ stage: state.stage, error: state.error }); // 等待期间被取消
      warn("info", `云伴登录完成：${auth.accountId}（${auth.loginMode}）`, [state.password, state.ticket]);
      succeed(auth);
      return reply({ stage: "done" });
    }
    if (out.sms) {
      state.stage = "sms";
      state.ticket = out.sms.ticket;
      state.mobile = out.sms.mobile;
      state.captchaFails = 0; // 验证码已过
      state.smsResends = 0; // 新挑战重新给 3 次重发
      state.smsResendLimit = false;
      return reply({ stage: "sms", mobile: state.mobile });
    }
    if (out.restart) {
      // 挑战作废（challenge_invalid / signature_invalid）：回验证码表单重新发起
      state.stage = "captcha";
      state.ticket = "";
      state.mobile = "";
      return reply({ stage: "captcha", error: `短信挑战已作废，请重新登录（${out.restart}）` });
    }
    if (out.retryCaptcha && !fromSms) {
      state.captchaFails++;
      warn("warn", `云伴登录验证码未通过（第 ${state.captchaFails} 次）：${out.retryCaptcha}`, [state.password, state.ticket]);
      if (state.captchaFails >= CAPTCHA_MAX_FAILS) {
        fail(`验证码连续 ${CAPTCHA_MAX_FAILS} 次未通过，请重新发起登录`);
        return reply({ stage: "failed", error: state.error });
      }
      return reply({ stage: "captcha", error: `验证码不对（${out.retryCaptcha}）` });
    }
    if (out.fatal) {
      warn("warn", `云伴登录未完成：${out.fatal}`, [state.password, state.ticket]);
      fail(out.fatal);
      // 返回 state.error（已按值擦除），不要回未经处理的 out.fatal——
      // fail() 已清空 state.password，reply() 的擦除拿不到原值
      return reply({ stage: "failed", error: state.error });
    }
    // 短信码不对但挑战还在：留在当前阶段
    return reply({ stage: "sms", error: out.retryCaptcha || "验证未通过，请重试" });
  };

  const page = startPage({
    ttlMs: TTL_MS,
    signal: lifeSignal,
    onRequest: async (url, req) => {
      if (url.pathname === "/" && req.method === "GET") {
        // token 只经 URL fragment 交给页面脚本（不进 HTML/Referer/历史记录）
        return pageResponse("云伴登录", `<script>${PAGE_JS}</script>`);
      }
      if (req.headers.get("x-login-token") !== pageToken) return json({ error: "页面已失效，请从 Magpie 重新打开" }, 403);
      if (url.pathname === "/state" && req.method === "GET") {
        return reply({ stage: state.stage, mobile: state.mobile, error: state.error, limit: state.smsResendLimit });
      }
      if (url.pathname === "/captcha" && req.method === "GET") {
        if (state.stage === "done" || state.stage === "failed") return reply({ stage: state.stage, error: state.error });
        if (state.stage !== "captcha") return reply({ stage: state.stage, error: "当前不在验证码阶段" });
        return withBusy(async () => {
          try {
            const r = await postAnon(base, "/auth/captcha", {}, { signal: state.signal, timeoutMs: 15000 });
            if (!r.ok || typeof r.json?.captchaId !== "string" || !r.json.captchaId || typeof r.json.image !== "string" || !r.json.image) {
              const [code, message] = r.ok ? ["upstream_error", "验证码响应缺少 captchaId/image"] : parseUpstreamError(r.status, r.text);
              return json({ error: `取验证码失败 [${code}] ${message}` });
            }
            return json({ captchaId: r.json.captchaId, image: r.json.image });
          } catch (e) {
            if (isNetworkError(e, state.signal)) return json({ error: networkErrorMessage(base, e) });
            throw e;
          }
        });
      }
      if (url.pathname === "/submit" && req.method === "POST") {
        if (state.stage === "done" || state.stage === "failed") return reply({ stage: state.stage, error: state.error });
        return withBusy(async () => {
          const body = parseParams(await readBody(req));
          // 页面选的登录方式要记住（重绘后 select 不再回到默认 local）
          if (!state.modeChosen && (body.loginMode === "sso" || body.loginMode === "local")) {
            state.mode = body.loginMode;
            state.modeChosen = true;
          }
          // 页面补填（宿主没问 prompts 时）；服务端已有的不被覆盖
          if (!state.username && body.username) state.username = String(body.username).trim();
          if (!state.password && body.password) state.password = String(body.password);
          if (!state.username) return reply({ stage: "captcha", error: "请填写账号" });
          if (!state.password) return reply({ stage: "captcha", error: "请填写密码" });
          state.stage = "captcha";
          state.ticket = "";
          state.mobile = "";
          // local 模式无 deviceId；iam 模式多一个 deviceId
          const fields = { username: state.username, password: state.password, captchaId: String(body.captchaId ?? ""), captchaCode: String(body.captchaCode ?? "") };
          const sso = state.mode === "sso";
          const out = await postLogin(base, sso ? "/auth/iam/login" : "/auth/login", sso ? { ...fields, deviceId: state.deviceId } : fields, state);
          return settleAttempt(out);
        });
      }
      if (url.pathname === "/sms" && req.method === "POST") {
        if (state.stage !== "sms") return reply({ stage: state.stage === "done" || state.stage === "failed" ? state.stage : "captcha", error: state.error });
        return withBusy(async () => {
          const body = parseParams(await readBody(req));
          const out = await postLogin(
            base,
            "/auth/iam/challenge",
            { ticket: state.ticket, username: state.username, password: state.password, code: String(body.code ?? "").trim(), deviceId: state.deviceId },
            state,
          );
          return settleAttempt(out, { fromSms: true });
        });
      }
      if (url.pathname === "/resend" && req.method === "POST") {
        if (state.stage !== "sms") return reply({ stage: state.stage === "done" || state.stage === "failed" ? state.stage : "captcha", error: "当前不在短信验证阶段，请刷新页面" });
        return withBusy(async () => {
          if (state.smsResendLimit) return reply({ stage: "sms", error: `重发已达 ${SMS_MAX_RESENDS} 次上限`, limit: true });
          state.smsResends++;
          const out = await resendSms(base, state);
          if (state.smsResends >= SMS_MAX_RESENDS) state.smsResendLimit = true;
          return reply({ stage: "sms", ...out, limit: state.smsResendLimit });
        });
      }
      return undefined;
    },
  });

  // 登录结束后本地页保留 30 秒，之后关闭
  done.then(() => {
    const t = setTimeout(() => page.stop(), 30 * 1000);
    t.unref?.();
  });

  return {
    url: `${page.url}/#t=${pageToken}`,
    instructions:
      state.modeChosen && state.mode === "sso"
        ? "在浏览器打开上面的地址：输入图形验证码，可能还需短信验证码。完成后自动返回。"
        : "在浏览器打开上面的地址：输入账号密码与图形验证码。完成后自动返回。",
    method: "auto",
    // 宿主调用 callback(undefined, { signal })：取消/超时 abort 的是这个 signal
    callback: async (_code, opts = {}) => {
      const cbSignal = opts?.signal;
      const onCancel = () => {
        fail("登录已取消");
        try {
          life.abort();
        } catch {}
      };
      if (cbSignal) {
        if (cbSignal.aborted) onCancel();
        else cbSignal.addEventListener("abort", onCancel, { once: true });
      }
      try {
        const result = await done;
        if (result.type === "failed") return result;
        // 账号键校验：完成时的作用域必须还是发起时的那个
        const nowKey = safeAccountKey(input, providerId);
        if (state.accountKey && nowKey && state.accountKey !== nowKey) {
          return { type: "failed", error: "登录会话与账号作用域不一致，请重新发起登录" };
        }
        return result;
      } finally {
        cbSignal?.removeEventListener("abort", onCancel);
      }
    },
    // 供测试读取；密码在登录结束时已清空
    _state: state,
    _page: page,
    _token: pageToken,
  };
}

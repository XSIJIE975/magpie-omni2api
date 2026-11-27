// 灵码浏览器登录：SSO → 本地回调页 → （多组织时）选择组织 → 完成。
// 每次 authorize 起一个独立的本地服务；凭据只通过宿主调用的 callback() 交出，
// 页面处理函数只调用上游、保存流程状态。
//
// 登录结果的形状由宿主定义：成功 {type:"success", …凭据}，失败 {type:"failed", error}。
// 返回值的 type 不是 "success" 时宿主按失败处理、不保存任何内容。
//
// 约定：
// - 回调里的凭据块放在请求局部变量里，不写入共享 state，并发回调互不影响
// - 登录结束后（settled），迟到的响应与回调不再改变状态；每次 await 之后复查
// - 回调 URL 带令牌：处理后立刻 303 到 /done；state 不匹配时 303 到错误页
// - /org 表单的页面令牌只经 URL fragment 交给浏览器，不出现在 HTML 里
// - state 里不保存令牌；多组织时凭据块只在内存的 pending 里过渡
// - 宿主取消或超时会中止 callback 的 signal，整个登录随之失败并关闭本地页
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startPage, pageResponse, escapeHtml, readBody, parseParams, randomUUID, safeAccountKey } from "../common/page.mjs";
import { log, redact, scrubValues } from "../common/http.mjs";
import { encode } from "./codec.mjs";
import { generatePkce, synthesizeMaterial } from "./crypto.mjs";
import { grantAuthInfos, parseCallbackAuth, parseCallbackToken, statusByToken } from "./upstream.mjs";
import { buildAuth } from "./session.mjs";

const TTL_MS = 10 * 60 * 1000; // 整个登录流程的上限
// 登录结束后本地页保留 30 秒（完成页的刷新、重发），之后关闭
const DONE_GRACE_MS = 30 * 1000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// machine_id 在同一台机器上跨登录保持不变：签名材料由 machineId + uid 派生，换了
// machine_id 就要重新合成。宿主给插件的 client.auth 只有 set / remove，authorize 里
// 读不到账号的旧记录，所以把它存在 os.tmpdir() 的文件里；文件丢失时生成新的。
// 文件内容不完全可信：只接受 UUID 形状（它会进入登录 URL、密钥派生和 B 族请求头）。
const DEFAULT_MACHINE_FILE = join(tmpdir(), "magpie-omni2api-lingma-machine.json");

function lastMachineId(file) {
  try {
    const v = JSON.parse(readFileSync(file, "utf8"));
    if (typeof v?.machineId === "string" && UUID_RE.test(v.machineId)) return v.machineId;
  } catch {}
  return "";
}

function saveMachineId(file, machineId) {
  try {
    // 先写临时文件再换名，并设私有权限：不跟随固定路径上可能存在的符号链接
    const tmp = `${file}.${process.pid}.${randomUUID()}.tmp`;
    writeFileSync(tmp, JSON.stringify({ machineId }), { mode: 0o600 });
    renameSync(tmp, file);
  } catch {}
}

// 登录 URL。state 是 2-{nonce}；回调校验时去掉 2- 前缀再比对（见 /auth/callback）。
export function loginUrl(base, { nonce, port, challenge, machineId }) {
  const q = new URLSearchParams({
    nonce,
    port: String(port),
    state: `2-${nonce}`,
    challenge,
    challenge_method: "S256",
    machine_id: machineId,
  });
  return `${base}/lingma/login?${q}`;
}

// 测试/工具：构造回调 URL 的 auth/token 块。
export function callbackBlocks({ uid, yxUid = "", name = "", sect, rt, expireTimeMs = 0 }) {
  const auth = encode(Buffer.from([uid, yxUid, name].join("\n"), "utf8"));
  const token = encode(Buffer.from([sect, rt, String(expireTimeMs)].join("\n"), "utf8"));
  return { auth, token };
}

export async function beginLogin(inputs, { input, client, base, providerId, signal, logFn, machineFile = DEFAULT_MACHINE_FILE }) {
  const info = logFn ?? ((level, msg, secrets) => log(client, level, msg, secrets));
  const machineId = lastMachineId(machineFile) || randomUUID(); // uuid v4 带连字符（36 字符）
  const nonce = randomUUID().replace(/-/g, ""); // uuid v4 去连字符（32 hex）
  // /org 表单的页面令牌：只经 URL fragment 交给浏览器，不进 HTML、Referer 和日志。
  // 回调 state 的 nonce 只用于校验回调，不出现在页面上。
  const pageToken = randomUUID();
  const { challenge } = generatePkce(); // verifier 用完即弃

  // 本次登录的生命周期信号：authorize 的 signal 或 callback 的 signal 中止时，
  // 关闭本地页并取消进行中的上游请求。
  const life = new AbortController();
  const lifeSignal = signal ? AbortSignal.any([signal, life.signal]) : life.signal;

  const state = {
    accountKey: safeAccountKey(input, providerId),
    stage: "waiting", // waiting | orgs | done | failed
    uid: "",
    yxUid: "",
    name: "",
    orgs: [],
    error: "",
  };
  // 多组织时等待用户选择的凭据块：只在内存里保存，登录结束即清空。
  let pending = null;
  let settled = false;
  let ttlTimer = null;

  let settle;
  const done = new Promise((resolve) => (settle = resolve));
  done.catch(() => {});
  // 只认第一次：浏览器重试回调，或超时与完成同时发生时，后续调用不再生效
  const fail = (message, secrets = []) => {
    if (settled) return;
    settled = true;
    state.stage = "failed";
    state.error = scrubValues(redact(message), secrets);
    pending = null;
    clearTimeout(ttlTimer);
    settle({ type: "failed", error: state.error });
  };
  const succeed = (fields) => {
    if (settled) return;
    settled = true;
    state.stage = "done";
    pending = null;
    clearTimeout(ttlTimer);
    settle({ type: "success", ...fields });
  };
  signal?.addEventListener("abort", () => fail("登录已取消"), { once: true });
  ttlTimer = setTimeout(() => fail("登录已超时，请重新发起"), TTL_MS);
  ttlTimer.unref?.();

  // 拿到令牌后的收尾：
  // - uid / name / userType 取自 user/status；expireTime 大于 0 才采用，否则沿用回调的
  // - 令牌用回调给的，不用 status 响应里的
  // - 组织以所选为准；status 返回了 orgId 时以它为准
  // cb 是回调里的凭据块（请求局部变量或 pending），不从共享 state 读。
  const completeWith = async (cb, orgId, orgName) => {
    const login = await statusByToken(base, orgId, cb.uid, cb.sect, { signal: lifeSignal, timeoutMs: 30000 });
    if (settled) return; // 等待期间被取消/超时：不再构建凭据
    // 完成页显示 status 校验后的身份（回调块里的姓名未经校验）
    state.uid = login.uid;
    state.name = login.name;
    const org = login.orgId ? { orgId: login.orgId, orgName: login.orgName } : { orgId, orgName };
    const materials = synthesizeMaterial(machineId, login.uid, login.name, org.orgId, org.orgName, info);
    const auth = buildAuth(
      {
        uid: login.uid,
        name: login.name,
        userType: login.userType,
        orgId: org.orgId,
        orgName: org.orgName,
        securityOauthToken: cb.sect,
        refreshToken: cb.rt,
        expireTimeMs: login.expireTimeMs > 0 ? login.expireTimeMs : cb.expireTimeMs,
      },
      materials,
      machineId,
    );
    saveMachineId(machineFile, machineId);
    info("info", `灵码登录完成：${auth.accountId}`, [cb.sect, cb.rt]);
    succeed(auth);
  };

  const donePage = () => pageResponse("登录完成", `<h1>登录完成</h1><p class="ok">${escapeHtml(state.name || state.uid)} 已登录，可关闭此页。</p>`);
  const failedPage = () => pageResponse("登录失败", `<h1>登录失败</h1><p class="err">${escapeHtml(state.error)}</p>`);
  // 303 到无令牌的页面：回调 URL（含 auth/token）不留在地址栏/历史里
  const seeOther = (to) =>
    new Response(null, {
      status: 303,
      headers: { location: to, "cache-control": "no-store", "referrer-policy": "no-referrer" },
    });
  const badPage = (message, status = 400) =>
    pageResponse("登录失败", `<h1>页面已失效</h1><p class="err">${escapeHtml(message)}</p>`, { status });

  let orgBusy = false; // 组织单选提交串行化（双击/多标签）

  const orgPage = () => {
    const radios = state.orgs
      .map((o, i) => {
        const label = o.orgName ? `${o.orgName}（${o.orgId}）` : o.orgId;
        return `<label><input type="radio" name="orgId" value="${escapeHtml(o.orgId)}" style="width:auto" ${i === 0 ? "checked" : ""}> ${escapeHtml(label)}</label>`;
      })
      .join("\n");
    return pageResponse(
      "选择组织",
      `<h1>选择组织</h1><p>该账号属于多个组织，请选择登录组织。</p>
<form method="POST" action="/org"><input type="hidden" name="t" id="t" value="">${radios}<button type="submit">选择并完成登录</button></form>
<script>const m=(location.hash||"").match(/[#&]t=([^&]*)/);if(m){document.getElementById("t").value=decodeURIComponent(m[1]);history.replaceState(null,"",location.pathname);}</script>`,
    );
  };

  const page = startPage({
    ttlMs: TTL_MS,
    signal: lifeSignal,
    onRequest: async (url, req) => {
      if (url.pathname === "/done" && req.method === "GET") {
        if (url.searchParams.get("e") === "state") return badPage("回调 state 与本次登录不匹配，请回到登录页重新发起。", 200);
        if (state.stage === "done") return donePage();
        if (state.stage === "failed") return failedPage();
        return pageResponse("登录进行中", "<h1>登录进行中</h1><p>还在等浏览器回调，请回到登录页完成 SSO。</p>");
      }
      if (url.pathname === "/auth/callback" && req.method === "GET") {
        if (settled) return seeOther("/done");
        if (state.stage === "orgs") return seeOther(`/org#t=${pageToken}`); // 浏览器重试：回组织选择页
        // state 参数带 2- 前缀时去掉再比对
        const callbackState = url.searchParams.get("state") ?? "";
        const bare = callbackState.startsWith("2-") ? callbackState.slice(2) : callbackState;
        if (bare !== nonce) {
          // state 不匹配的回调（其它来源）：不判失败，303 到不带令牌的错误页
          return seeOther("/done?e=state");
        }
        let cb;
        try {
          const authBlock = parseCallbackAuth(url.searchParams.get("auth") ?? "");
          const tokenBlock = parseCallbackToken(url.searchParams.get("token") ?? "");
          cb = {
            uid: authBlock.uid,
            sect: tokenBlock.securityOauthToken,
            rt: tokenBlock.refreshToken,
            expireTimeMs: tokenBlock.expireTimeMs,
          };
          state.uid = authBlock.uid;
          state.yxUid = authBlock.yxUid;
          state.name = authBlock.name;
        } catch (e) {
          fail(e?.message ?? "回调参数解析失败");
          return seeOther("/done");
        }
        let orgs;
        try {
          orgs = await grantAuthInfos(base, cb.uid, cb.sect, { signal: lifeSignal, timeoutMs: 30000 });
        } catch (e) {
          fail(e?.message ?? "组织列表获取失败", [cb.sect, cb.rt]);
          return seeOther("/done");
        }
        if (settled) return seeOther("/done"); // 等待期间被取消/超时
        // 0 或 1 个组织：自动选定（0 个时 orgId / orgName 为空）
        if (orgs.length <= 1) {
          try {
            await completeWith(cb, orgs[0]?.orgId ?? "", orgs[0]?.orgName ?? "");
          } catch (e) {
            fail(e?.message ?? "登录收尾失败", [cb.sect, cb.rt]);
          }
          return seeOther("/done");
        }
        // 多组织：在本地页上选择。组织列表要等回调之后才知道，不能用宿主的
        // prompts select。表单提交到 /org，页面令牌只经 fragment 传递。
        pending = cb;
        state.stage = "orgs";
        state.orgs = orgs;
        return seeOther(`/org#t=${pageToken}`);
      }
      if (url.pathname === "/org" && req.method === "GET") {
        if (settled) return seeOther("/done");
        if (state.stage !== "orgs") return badPage("当前不在组织选择阶段，请重新发起登录。");
        return orgPage();
      }
      if (url.pathname === "/org" && req.method === "POST") {
        if (settled) return seeOther("/done");
        const body = parseParams(await readBody(req));
        // 页面令牌只经 fragment 交给浏览器：别的本机进程拿不到，也就发不出合法表单
        if (body.t !== pageToken) return badPage("页面已失效，请重新发起登录。");
        if (state.stage !== "orgs" || !pending) return badPage("当前不在组织选择阶段，请重新发起登录。");
        if (orgBusy) return badPage("正在完成登录，请稍候刷新 /done。");
        orgBusy = true;
        try {
          const org = state.orgs.find((o) => o.orgId === String(body.orgId ?? ""));
          if (!org) return badPage(`未知组织：${body.orgId}`);
          const cb = pending;
          try {
            await completeWith(cb, org.orgId, org.orgName);
          } catch (e) {
            fail(e?.message ?? "登录收尾失败", [cb.sect, cb.rt]);
          }
          return seeOther("/done");
        } finally {
          orgBusy = false;
        }
      }
      return undefined;
    },
  });
  // 登录结束后保留 DONE_GRACE_MS 再关闭本地页
  done.then(() => {
    const t = setTimeout(() => page.stop(), DONE_GRACE_MS);
    t.unref?.();
  });

  return {
    url: loginUrl(base, { nonce, port: page.port, challenge, machineId }),
    instructions: "在浏览器打开上面的地址完成灵码 SSO 登录，完成后自动返回（多组织账号需选一个组织）。",
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
    // 供测试读取；不含令牌
    _state: state,
    _page: page,
    _nonce: nonce,
    _token: pageToken,
  };
}

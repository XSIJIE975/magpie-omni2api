// 灵码上游客户端：浏览器登录换取（A 族）、模型目录（B 族）、
// 对话（B 族 SSE → 统一事件流）。
import { fetchJson, openStream, readErrorText, sseLines, isNetworkError, networkErrorMessage, md5hex, randomUUID, redact } from "../common/http.mjs";
import { encode, decode } from "./codec.mjs";
import { aHeaders, bPayloadB64, bSignature, bAuthorization, COSY_VERSION } from "./crypto.mjs";

// ---------------- 错误分类 ----------------

// A 族接口与模型目录的错误分类：401 → AuthExpired；≥500 → Unavailable；其余 → BadRequest。
// AuthExpired 回 401 并带 X-Magpie-Sign-In: expired，其余带 kept。
// 这些失败不是调用方造成的，回给调用方的状态码是 401 或 502。
export function classifiedError(status, message) {
  const kind = status === 401 ? "AuthExpired" : status >= 500 ? "Unavailable" : "BadRequest";
  const e = new Error(message);
  e.kind = kind;
  e.status = status;
  e.signIn = kind === "AuthExpired" ? "expired" : "kept";
  e.httpStatus = kind === "AuthExpired" ? 401 : 502;
  return e;
}

// chat 的状态分类：401 → AuthExpired；429 → RateLimited；其余 4xx → BadRequest；
// ≥500 与 3xx → Unavailable（3xx 是跳转，带凭据的请求不跟随跳转）。
// httpStatus 是回给调用方的状态：401 / 429 / 400 / 502。
export function chatError(status, text) {
  const redirect = status >= 300 && status < 400;
  const kind =
    status === 401 ? "AuthExpired" : status === 429 ? "RateLimited" : redirect || status >= 500 ? "Unavailable" : "BadRequest";
  // 错误文本会出现在调用方可见的 message 和宿主日志里：先脱敏再截断
  const body = redact(String(text ?? "")).slice(0, 300);
  const e = new Error(
    redirect ? `上游 HTTP ${status}: 返回了跳转而不是流式响应` : `上游 HTTP ${status}${body ? `: ${body}` : ""}`,
  );
  e.kind = kind;
  e.status = status;
  e.signIn = kind === "AuthExpired" ? "expired" : "kept";
  e.httpStatus = kind === "AuthExpired" ? 401 : kind === "RateLimited" ? 429 : kind === "BadRequest" ? 400 : 502;
  return e;
}

export function networkError(base, e) {
  const err = new Error(networkErrorMessage(base, e));
  err.kind = "Unavailable";
  err.signIn = "kept";
  err.httpStatus = 502;
  return err;
}

// ---------------- A 族（登录面） ----------------

// A 族 POST：请求体是 customB64 编码的 payload 信封，响应是明文 JSON
// （兼容包在 content 字段里的形式）。
export async function aPost(base, path, innerPayload, opts = {}) {
  const envelope = { payload: JSON.stringify(innerPayload), encodeVersion: "1" };
  const wire = encode(Buffer.from(JSON.stringify(envelope), "utf8"));
  const headers = Object.fromEntries(aHeaders());
  let r;
  try {
    r = await fetchJson(
      `${base}${path}?Encode=1`,
      {
        method: "POST",
        headers: {
          ...headers,
          "content-type": "application/json",
          "user-agent": "Go-http-client/1.1",
          "accept-encoding": "identity",
          "x-request-id": randomUUID(),
        },
        body: wire,
        signal: opts.signal,
      },
      { timeoutMs: opts.timeoutMs ?? 30000 },
    );
  } catch (e) {
    if (isNetworkError(e, opts.signal)) throw networkError(base, e);
    throw e;
  }
  if (!r.ok) {
    // 错误消息会原样进入宿主日志：响应体先脱敏
    throw classifiedError(r.status, `上游 HTTP ${r.status}${r.text ? `: ${redact(r.text).slice(0, 300)}` : ""}`);
  }
  if (r.json === undefined) {
    throw Object.assign(new Error(`上游响应非 JSON${r.text ? `: ${redact(r.text).slice(0, 200)}` : ""}`), {
      kind: "Internal",
      signIn: "kept",
    });
  }
  const v = r.json;
  if (v?.content && typeof v.content === "object") return v.content; // 宽容包裹
  return v;
}

// 用会话令牌查用户态（浏览器登录回调后的换取步骤）。
export async function statusByToken(base, orgId, userId, token, opts = {}) {
  const inner = {
    orgId,
    userId,
    token,
    personalToken: "",
    securityOauthToken: "",
    refreshToken: "",
    needRefresh: false,
    authInfo: {},
  };
  const v = await aPost(base, "/algo/api/v3/user/status", inner, opts);
  return parseLoginResponse(v);
}

// 组织授权列表。
export async function grantAuthInfos(base, userId, token, opts = {}) {
  const v = await aPost(base, "/algo/api/v3/user/grantAuthInfos", { userId, token }, opts);
  const arr = Array.isArray(v) ? v : Array.isArray(v?.content) ? v.content : [];
  return arr
    .filter((o) => typeof o?.orgId === "string" && o.orgId)
    .map((o) => ({ orgId: o.orgId, orgName: typeof o.orgName === "string" ? o.orgName : "" }));
}

// refresh_token 续期。上游 401 或响应缺用户 id 时抛 signIn "expired"（需要重新浏览器登录）；
// 网络与 5xx 失败带 kept。
export async function refreshSession(base, refreshToken, userId, opts = {}) {
  const v = await aPost(base, "/algo/api/v3/user/refresh_token", { userId, refreshToken, needRefresh: true }, opts);
  return parseLoginResponse(v);
}

// 解析 LoginResponse（字段在响应顶层）：id → uid、name、userType、orgId、orgName、
// securityOauthToken、refreshToken、expireTime（毫秒）。uid 缺失视为登录失效。
// 错误消息不带响应体：refresh 抛出的错误会原样写进宿主日志，而成功响应的正文里
// 就是两个明文令牌。
export function parseLoginResponse(v) {
  const g = (k) => (typeof v?.[k] === "string" ? v[k] : "");
  const resp = {
    uid: g("id"),
    name: g("name"),
    userType: g("userType"),
    orgId: g("orgId"),
    orgName: g("orgName"),
    securityOauthToken: g("securityOauthToken"),
    refreshToken: g("refreshToken"),
    expireTimeMs: typeof v?.expireTime === "number" ? v.expireTime : 0,
  };
  if (!resp.uid) {
    throw Object.assign(new Error("登录响应缺少用户 id（令牌无效或已过期）"), {
      kind: "Auth",
      signIn: "expired",
      httpStatus: 401,
    });
  }
  return resp;
}

// ---------------- 浏览器回调块解析 ----------------

// auth 块：customB64 → 三行 uid / yxUid / 姓名（每行 trim）。
export function parseCallbackAuth(wire) {
  const text = decode(wire).toString("utf8");
  const [uid = "", yxUid = "", name = ""] = text.split("\n").map((s) => s.trim());
  if (!uid) throw Object.assign(new Error("回调 auth 块缺少用户 id"), { signIn: "kept" });
  return { uid, yxUid, name };
}

// token 块：customB64 → 三行 securityOauthToken / refreshToken / expireTime 毫秒。
export function parseCallbackToken(wire) {
  const text = decode(wire).toString("utf8");
  const [sect = "", rt = "", expire = ""] = text.split("\n").map((s) => s.trim());
  if (!sect || !rt) throw Object.assign(new Error("回调 token 块缺少会话令牌"), { signIn: "kept" });
  const n = Number.parseInt(expire, 10);
  // 超长数字串会解析成 Infinity（JSON 落盘变 null、永不再续期）：只收有限正值
  return { securityOauthToken: sect, refreshToken: rt, expireTimeMs: Number.isFinite(n) && n > 0 ? n : 0 };
}

// ---------------- B 族（会话面） ----------------

// B 族请求头。cosy-date 与签名用的 ts 必须是同一个字符串。
export function bHeaders(auth, sigpath, wire) {
  const ts = Math.floor(Date.now() / 1000).toString(); // Unix 秒
  const payload = bPayloadB64(auth.encryptUserInfo, randomUUID(), COSY_VERSION);
  const sig = bSignature(payload, auth.key, ts, wire, sigpath);
  return {
    authorization: bAuthorization(payload, sig),
    "content-type": "application/json",
    accept: "application/json",
    "accept-encoding": "identity",
    "cache-control": "no-cache",
    "cosy-key": auth.key,
    "cosy-date": ts,
    "cosy-bodyhash": md5hex(wire),
    "cosy-bodylength": String(Buffer.byteLength(wire, "utf8")),
    "cosy-sigpath": sigpath,
    "cosy-user": auth.uid,
    "cosy-organization-id": auth.organizationId,
    "cosy-organization-tags": "",
    "cosy-machineid": auth.machineId,
    "cosy-machineos": "x86_64_windows",
    "cosy-machinetoken": "",
    "cosy-machinetype": "",
    "cosy-clienttype": "2",
    "cosy-clientip": "169.254.26.114",
    "cosy-data-policy": "DISAGREE",
    "cosy-version": COSY_VERSION,
    "login-version": "v2",
    "user-agent": "Go-http-client/1.1",
  };
}

// GET /algo/api/v2/model/list（空 body：wire=""、bodylength 0、bodyhash md5("")）。
export async function modelList(base, auth, opts = {}) {
  let r;
  try {
    r = await fetchJson(
      `${base}/algo/api/v2/model/list`,
      {
        method: "GET",
        headers: { ...bHeaders(auth, "/api/v2/model/list", ""), "x-request-id": randomUUID() },
        signal: opts.signal,
      },
      { timeoutMs: opts.timeoutMs ?? 20000 },
    );
  } catch (e) {
    if (isNetworkError(e, opts.signal)) throw networkError(base, e);
    throw e;
  }
  if (r.status === 401) throw classifiedError(401, `上游 401${r.text ? `: ${redact(r.text).slice(0, 200)}` : ""}`);
  if (!r.ok) throw classifiedError(r.status, `model/list HTTP ${r.status}${r.text ? `: ${redact(r.text).slice(0, 200)}` : ""}`);
  if (r.json === undefined) throw Object.assign(new Error("model/list 响应非 JSON"), { kind: "Internal", signIn: "kept" });
  return parseModelList(r.json);
}

// 按 chat/developer/assistant/inline 四类顺序遍历；空 key 跳过；按 key 去重
// （首次出现为准）；display_name 缺失回退 key；目录里其它分类（如 quest）不取。
export function parseModelList(v) {
  const out = [];
  const seen = new Set();
  for (const cat of ["chat", "developer", "assistant", "inline"]) {
    const items = v?.[cat];
    if (!Array.isArray(items)) continue;
    for (const m of items) {
      const key = typeof m?.key === "string" ? m.key : "";
      if (!key || seen.has(key)) continue;
      seen.add(key);
      out.push({
        key,
        displayName: typeof m.display_name === "string" && m.display_name ? m.display_name : key,
        category: cat,
        maxInputTokens: typeof m.max_input_tokens === "number" ? m.max_input_tokens : 0,
      });
    }
  }
  return out;
}

// POST agent_chat_generation，解析为统一事件流。
// 一律用短连接（connection: close）：部分代理与负载均衡在复用连接上会截断 SSE。
// 不设总超时：只有建连超时与首字节 / 空闲超时。
export async function chatStream(base, auth, agentBody, setId, opts = {}) {
  const algoPath = "/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1";
  const sigpath = "/api/v2/service/pro/sse/agent_chat_generation";
  const wire = encode(Buffer.from(JSON.stringify(agentBody), "utf8"));
  let resp;
  try {
    resp = await openStream(
      `${base}${algoPath}`,
      {
        method: "POST",
        headers: {
          ...bHeaders(auth, sigpath, wire),
          accept: "text/event-stream",
          connection: "close",
          "x-request-id": setId,
          "x-model-key": agentBody?.model_config?.key ?? "",
          "x-model-name": "",
          "x-model-source": "organization",
        },
        body: wire,
        signal: opts.signal,
      },
      { firstByteMs: opts.firstByteMs ?? 30000 },
    );
  } catch (e) {
    if (isNetworkError(e, opts.signal)) throw networkError(base, e);
    throw e; // 调用方取消：原样抛出
  }
  if (!resp.ok) {
    const text = await readErrorText(resp);
    throw chatError(resp.status, text);
  }
  // 上游用 200 返回非流式内容（JSON 错误信封 / 网关的 HTML 页）时，报「上游未返回
  // 流式响应」（502）；否则非流式正文会被解析成一个没有内容的回答。
  // content-type 不是这两种时仍按 SSE 解析。
  const ct = resp.headers.get("content-type") ?? "";
  if (!ct.includes("event-stream") && (ct.includes("json") || ct.includes("html"))) {
    const text = await readErrorText(resp, { limit: 2 * 1024 });
    const e = new Error(`上游未返回流式响应${text ? `: ${text.slice(0, 200)}` : ""}`);
    e.kind = "Unavailable";
    e.signIn = "kept";
    e.status = 502;
    e.httpStatus = 502;
    throw e;
  }
  return parseChatEvents(resp, opts);
}

// SSE 响应解析为统一事件：
// - 只处理 data: 行；内容不是 JSON 的忽略
// - statusCode 存在且不是 "OK"（区分大小写）→ error 事件，随后结束
// - 没有 statusCode → 控制帧，直接结束
// - body 是字符串时再解析一次 JSON，失败则丢弃这一帧
// - delta 里的 content / reasoning_content / tool_calls → 对应事件；finish_reason 非空 → finish
// - usage.total_tokens > 0 → usage
// - 收到 finish 后先处理完同一批里剩下的行（同一帧里的 usage 要取到），再结束
async function* parseChatEvents(resp, opts = {}) {
  let finishSeen = false;
  let ended = false;
  for await (const lines of sseLines(resp, { firstByteMs: opts.firstByteMs ?? 30000, idleMs: opts.idleMs ?? 180000 })) {
    for (const line of lines) {
      if (ended) break;
      if (line.startsWith("event:")) continue;
      if (!line.startsWith("data:")) continue;
      let ev;
      try {
        ev = JSON.parse(line.slice(5).trim());
      } catch {
        continue; // 非事件行（心跳等）
      }
      const sc = typeof ev?.statusCode === "string" ? ev.statusCode : undefined;
      if (sc !== undefined && sc !== "OK") {
        const raw = typeof ev?.body === "string" ? ev.body : ev?.body != null ? JSON.stringify(ev.body) : sc;
        const message = redact(raw).slice(0, 300);
        yield { type: "error", message, code: sc };
        ended = true;
        break;
      }
      if (sc === undefined) {
        ended = true; // 控制事件（finish/指标信封），无正文
        break;
      }
      const body = ev?.body;
      let inner = body;
      if (typeof body === "string") {
        try {
          inner = JSON.parse(body);
        } catch {
          continue; // 二次解析失败：整帧丢弃
        }
      }
      if (inner && Array.isArray(inner.choices)) {
        for (const ch of inner.choices) {
          const d = ch?.delta;
          if (d) {
            if (typeof d.content === "string" && d.content) yield { type: "content", text: d.content };
            if (typeof d.reasoning_content === "string" && d.reasoning_content) yield { type: "reasoning", text: d.reasoning_content };
            if (d.tool_calls != null) yield { type: "tool_calls", toolCalls: d.tool_calls };
          }
          if (typeof ch?.finish_reason === "string" && ch.finish_reason) {
            finishSeen = true;
            yield { type: "finish", reason: ch.finish_reason };
          }
        }
      }
      if (inner?.usage && typeof inner.usage === "object" && inner.usage.total_tokens > 0) {
        yield { type: "usage", usage: inner.usage };
      }
    }
    if (ended || finishSeen) break;
  }
}

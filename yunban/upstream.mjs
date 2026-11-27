// 云伴上游客户端：匿名接口（登录链路 /auth/*）+ 签名接口（/me、/me/models、
// /me/account、/v1 透传）。
import { fetchJson, openStream, isNetworkError, networkErrorMessage, redact } from "../common/http.mjs";
import { signRequest } from "./sign.mjs";

// 上游客户端使用的请求头（openai-node 4.104.0 的默认值）。
const STAINLESS_HEADERS = {
  "x-stainless-lang": "js",
  "x-stainless-package-version": "4.104.0",
  "x-stainless-os": "Windows_NT",
  "x-stainless-arch": "x64",
  "x-stainless-runtime": "node",
  "x-stainless-runtime-version": "v22.16.0",
  "x-stainless-retry-count": "0",
  "user-agent": "OpenAI/JS 4.104.0",
};

function decorate(init, timeoutSecs = 300) {
  return {
    ...init,
    headers: { ...STAINLESS_HEADERS, "x-stainless-timeout": String(timeoutSecs), ...(init.headers ?? {}) },
  };
}

// 匿名 POST（登录链路：/auth/captcha、/auth/login、/auth/iam/*）。body 可为对象/字符串。
export async function postAnon(base, path, body, opts = {}) {
  const hasBody = body !== undefined && body !== null;
  return fetchJson(
    `${base}${path}`,
    decorate({
      method: "POST",
      headers: { accept: "application/json", ...(hasBody ? { "content-type": "application/json" } : {}) },
      body: hasBody ? (typeof body === "string" ? body : JSON.stringify(body)) : undefined,
      signal: opts.signal,
    }),
    { timeoutMs: opts.timeoutMs ?? 30000 },
  );
}

// 签名 POST（Bearer + X-Banban-Timestamp/Nonce/Signature）。body 为 null 时无体，
// 签名方法串仍固定 POST。
export async function postSigned(base, token, sessionKey, path, body, opts = {}) {
  const bytes = body ? (typeof body === "string" ? Buffer.from(body, "utf8") : Buffer.from(body)) : null;
  const sig = signRequest(sessionKey, "POST", path, bytes ?? undefined);
  return fetchJson(
    `${base}${path}`,
    decorate({
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/json",
        "x-banban-timestamp": sig.timestamp,
        "x-banban-nonce": sig.nonce,
        "x-banban-signature": sig.signature,
        ...(bytes ? { "content-type": "application/json" } : {}),
      },
      body: bytes ?? undefined,
      signal: opts.signal,
    }),
    { timeoutMs: opts.timeoutMs ?? 20000 },
  );
}

// 签名 POST，返回原始 Response（/v1/chat/completions 按字节透传，body 流交给调用方）。
// 只给「建连 + 响应头」设超时（firstByteMs），响应头到达后解除：
// AbortSignal.timeout 一旦传给 fetch，到点会把还在读取的 body 一起中断。
export async function postSignedRaw(base, token, sessionKey, path, body, opts = {}) {
  const bytes = body ? (typeof body === "string" ? Buffer.from(body, "utf8") : Buffer.from(body)) : null;
  const sig = signRequest(sessionKey, "POST", path, bytes ?? undefined);
  return openStream(
    `${base}${path}`,
    {
      method: "POST",
      headers: {
        ...STAINLESS_HEADERS,
        "x-stainless-timeout": "300",
        authorization: `Bearer ${token}`,
        accept: "application/json",
        "x-banban-timestamp": sig.timestamp,
        "x-banban-nonce": sig.nonce,
        "x-banban-signature": sig.signature,
        ...(bytes ? { "content-type": "application/json" } : {}),
      },
      body: bytes ?? undefined,
      signal: opts.signal,
    },
    { firstByteMs: opts.firstByteMs ?? 60000 },
  );
}

// 签名 POST 并断言 2xx，返回 JSON；失败抛带 signIn 标记的错误。
export async function signedJson(base, token, sessionKey, path, opts = {}) {
  let r;
  try {
    r = await postSigned(base, token, sessionKey, path, null, opts);
  } catch (e) {
    if (isNetworkError(e, opts.signal)) {
      throw Object.assign(new Error(networkErrorMessage(base, e)), { kind: "Unavailable", signIn: "kept" });
    }
    throw e;
  }
  if (!r.ok) {
    const [code, message] = parseUpstreamError(r.status, r.text);
    throw classifiedError(r.status, code, message);
  }
  if (r.json === undefined) {
    throw Object.assign(new Error(`上游响应格式变化：${path} 响应不是 JSON`), { kind: "Unavailable", signIn: "kept" });
  }
  return r.json;
}

// ---------------- 错误信封与分类 ----------------

// 解析上游的错误响应：
// 1. {"error":{"code","message"}} → error.code（不是字符串时用 upstream_error）
// 2. {"ErrorCode","ErrorMessage"} → code 转小写、空格换成 _
// 3. 都不是 → code 为 upstream_status_{status}，message 为响应正文
// 文案会出现在调用方可见的响应和宿主日志里：先脱敏，再截断到 300 字符。
export function parseUpstreamError(status, text) {
  let v;
  try {
    v = JSON.parse(text);
  } catch {
    v = null;
  }
  const clean = (s) => redact(String(s ?? "")).slice(0, 300);
  if (v && typeof v === "object") {
    const err = v.error;
    if (err && typeof err === "object") {
      const code = typeof err.code === "string" ? err.code : "upstream_error";
      const message = clean(typeof err.message === "string" ? err.message : "(上游未提供错误信息)");
      return [code, message];
    }
    if (typeof v.ErrorCode === "string") {
      const code = v.ErrorCode.toLowerCase().replace(/ /g, "_");
      const message = clean(typeof v.ErrorMessage === "string" ? v.ErrorMessage : "(上游未提供错误信息)");
      return [code, message];
    }
  }
  const snippet = clean(String(text ?? "").trim());
  return [`upstream_status_${status}`, snippet || `上游返回 HTTP ${status}`];
}

// 状态分类：401 → AuthExpired；403 → Auth；429 → RateLimited；3xx 与 ≥500 → Unavailable
// （带凭据的请求不跟随跳转）；其余 → BadRequest。
export function errorKindOf(status) {
  if (status === 401) return "AuthExpired";
  if (status === 403) return "Auth";
  if (status === 429) return "RateLimited";
  if (status >= 500 || (status >= 300 && status < 400)) return "Unavailable";
  return "BadRequest";
}

// 分类错误对象：kind 与 signIn（401 → expired，要求重新登录；其余 kept）。
// httpStatus 是回给调用方的状态：401 / 429；其它 4xx → 400；3xx 与 5xx → 502。
export function classifiedError(status, code, message) {
  const kind = errorKindOf(status);
  const e = new Error(`[${code}] ${message}`);
  e.kind = kind;
  e.status = status;
  e.signIn = kind === "AuthExpired" ? "expired" : "kept";
  e.httpStatus = kind === "AuthExpired" ? 401 : kind === "RateLimited" ? 429 : kind === "Unavailable" ? 502 : 400;
  return e;
}

// 两个 provider 共用：fetch 封装与超时、错误响应、脱敏日志、哈希。
// 只用 node:crypto 与全局 fetch。
import { createHash, createHmac, randomUUID } from "node:crypto";

export { randomUUID };

// ---------------- 哈希 ----------------

export function md5hex(data) {
  return createHash("md5").update(data).digest("hex");
}

export function sha256hex(data) {
  return createHash("sha256").update(data).digest("hex");
}

export function hmacSha256Hex(key, data) {
  return createHmac("sha256", key).update(data).digest("hex");
}

// ---------------- 脱敏日志 ----------------

// 按结构脱敏：JSON 的 "k": "v"（含转义形式）、URL 查询参数、`k: v` / `k=v` 写法里的
// 令牌与密码字段替换为 ***。按原值擦除见 scrubValues。
export function redact(s) {
  let out = String(s ?? "");
  // authorization 整行擦掉（Basic / Bearer 都算），先于下面的 Bearer 规则
  out = out.replace(/\b(authorization)\s*[:=]\s*[^\r\n;]+/gi, "$1=***");
  out = out.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/g, "Bearer ***");
  out = out.replace(
    /(\\?"[^"\\]*(?:token|session_?key|password|authorization|secret_?key|private_?key|secret|api_?key|encrypt_?user_?info|cosy-key|access)\\?"\s*:\s*\\?")[^"\\]*(\\?")/gi,
    "$1***$2",
  );
  out = out.replace(/(\\?"(?:refresh|key)\\?"\s*:\s*\\?")[^"\\]*(\\?")/g, "$1***$2");
  // URL 查询参数里的令牌
  out = out.replace(/([?&](?:token|access_token|refresh_token|session_?key)=)[^&\s]+/gi, "$1***");
  // 头式 `k: v` / `k=v`（authorization 已在上面整体处理）
  out = out.replace(
    /\b(cosy-key|session_?key|refresh_?token|securityOauthToken|access_?token|password)\s*[:=]\s*[^\s,;"']+/gi,
    "$1=***",
  );
  // 自由文本里的「invalid token sk-abc」形状（上游错误正文常见）
  out = out.replace(/\b((?:invalid|bad|expired|unknown|missing|revoked)[\s_-]*(?:token|session))\s+[A-Za-z0-9._~+/=-]{4,}/gi, "$1 ***");
  // 上游正文可能夹 CR/LF/C0 控制符伪造日志行；也限制单条长度
  out = out.replace(/[\u0000-\u001f\u007f]+/g, " ");
  return out.length > 2000 ? `${out.slice(0, 2000)}…` : out;
}

// 按原值擦除已知的秘密（令牌 / 密码 / 机器码）。长的先替换，避免短秘密是长秘密的
// 前缀时留下后缀；不设长度下限。
export function scrubValues(s, secrets = []) {
  let out = String(s ?? "");
  const list = [...new Set(secrets.filter((v) => typeof v === "string" && v))].sort((a, b) => b.length - a.length);
  for (const v of list) out = out.split(v).join("***");
  return out;
}

// 日志走宿主 client.app.log（不要直接 console）。secrets：已知秘密原值（可选）。
export function log(client, level, message, secrets = []) {
  try {
    // 先按结构脱敏，再按值擦除：反过来会先改掉 "password" 这类键名里的秘密子串，
    // 键名匹配失效。
    void Promise.resolve(client?.app?.log?.({ level, message: scrubValues(redact(message), secrets), service: "magpie-omni2api" })).catch?.(() => {});
  } catch {}
}

// ---------------- 错误响应 ----------------

// OpenAI 风格错误响应，带显式的 X-Magpie-Sign-In 头。
// signIn: "kept"（账号状态不变）| "expired"（要求重新登录）| undefined（不带该头）。
export function errorResponse(status, message, signIn) {
  const headers = { "content-type": "application/json" };
  if (signIn) headers["x-magpie-sign-in"] = signIn;
  return new Response(
    JSON.stringify({
      error: {
        message,
        type: status === 429 ? "rate_limit_error" : "api_error",
        code: null,
      },
    }),
    { status, headers },
  );
}

// ---------------- 配置取值 ----------------

// 正整数配置项，非法值回落到默认值，上限 24 小时。下限取 1：小数向下取整后可能是 0，
// setTimeout(…, 0) 会立即触发超时。
export function intOption(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 1 ? Math.min(Math.floor(n), 24 * 3600 * 1000) : fallback;
}

// ---------------- fetch 超时 ----------------

// 判断上游是否不可达（DNS 失败 / 拒连 / 连接被重置 / 超时）。
// 调用方的 signal 已中止时不算：那是调用方取消，由调用方原样抛出。
// 错误码在 Node 与 Bun 下拼写不同，两套都认，再用消息文本兜底。
const NETWORK_CODES = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "ENOTFOUND",
  "EAI_AGAIN",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ENETDOWN",
  "EPIPE",
  "UND_ERR_CONNECT_TIMEOUT",
  "CERT_HAS_EXPIRED",
  "ConnectionRefused",
  "ConnectionReset",
  "ConnectionClosed",
  "ConnectTimeout",
  "ConnectionTimeout",
  "GetDnsFailed",
  "NetworkError",
  "TLSConnectionClosed",
]);
const NETWORK_WORDS =
  /unable to connect|socket connection (was )?closed|is the computer able to access|getaddrinfo|dns|timed out|connection (timed out|timeout|refused|reset)/i;

export function isNetworkError(e, signal) {
  if (signal?.aborted && e?.name === "AbortError") return false;
  if (e?.name === "TimeoutError") return true;
  const code = e?.cause?.code ?? e?.code;
  if (typeof code === "string" && NETWORK_CODES.has(code)) return true;
  return e instanceof TypeError && NETWORK_WORDS.test(String(e?.message ?? ""));
}

const NETWORK_HINT = "（请检查网络或 VPN；上游可能位于私有网络）";

export function networkErrorMessage(base, e) {
  const code = String(e?.cause?.code ?? e?.code ?? "");
  const msg = String(e?.message ?? e);
  let hint = NETWORK_HINT;
  if (/CERT_|certificate|TLS/i.test(`${code} ${msg}`)) hint = "（证书校验失败：检查代理或 VPN）";
  else if (e?.name === "TimeoutError" || /timed out|timeout/i.test(`${code} ${msg}`)) hint = "（连接超时：检查网络或 VPN）";
  return `无法连接 ${base}: ${msg}${hint}`;
}

// 宿主给的请求体（string / ArrayBuffer / TypedArray）转文本。
export function bodyTextOf(init) {
  const body = init?.body;
  if (body == null) return "";
  if (typeof body === "string") return body;
  if (body instanceof ArrayBuffer) return new TextDecoder().decode(body);
  if (ArrayBuffer.isView(body)) return new TextDecoder().decode(new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
  return "";
}

// 读非 2xx 响应体，用于错误文案：总限时（默认 5s）+ 限长（默认 16KB，按字符计）。
// openStream 的超时在响应头到达后就解除，所以错误体要自己限时：
// 上游发完响应头后不再发送 body 时，请求不能一直挂着。
export async function readErrorText(resp, { timeoutMs = 5000, limit = 16 * 1024 } = {}) {
  if (!resp?.body) return "";
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let out = "";
  let timer = null;
  let timedOut = false;
  const deadline = Date.now() + timeoutMs;
  const arm = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      timedOut = true;
      reader.cancel("error body timeout").catch(() => {}); // 挂起的 read 解析为 done
    }, Math.max(0, deadline - Date.now()));
    timer.unref?.();
  };
  try {
    while (!timedOut && out.length < limit) {
      arm();
      let r;
      try {
        r = await reader.read();
      } finally {
        clearTimeout(timer);
      }
      if (r.done) break;
      const piece = decoder.decode(r.value, { stream: true });
      if (piece) out += piece.slice(0, Math.max(0, limit - out.length));
    }
  } catch {
  } finally {
    clearTimeout(timer);
    reader.cancel().catch(() => {});
    try {
      reader.releaseLock();
    } catch {}
  }
  return out;
}

// 读 JSON 接口的响应体，超过上限（默认 4MB）时取消连接并报错。
// 所有插件共用宿主的一个 Bun 进程，没有上限时异常大的响应体会占满它的内存。
async function readTextCapped(resp, limit = 4 * 1024 * 1024) {
  if (!resp.body) return "";
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let out = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      out += decoder.decode(value, { stream: true });
      if (out.length > limit) throw new Error("上游响应过大");
    }
    out += decoder.decode();
  } finally {
    reader.cancel().catch(() => {});
    try {
      reader.releaseLock();
    } catch {}
  }
  return out;
}

// 短请求（登录 / 续期 / 模型列表）：总超时兜底 + 响应体限长。
export async function fetchJson(url, init = {}, { timeoutMs = 20000 } = {}) {
  const signal = AbortSignal.any(
    init.signal ? [init.signal, AbortSignal.timeout(timeoutMs)] : [AbortSignal.timeout(timeoutMs)],
  );
  const resp = await fetch(url, { ...init, signal, redirect: "manual" });
  const text = await readTextCapped(resp);
  let json = undefined;
  try {
    json = JSON.parse(text);
  } catch {}
  return { status: resp.status, ok: resp.status >= 200 && resp.status < 300, headers: resp.headers, text, json };
}

// 空闲超时文案（「上游流超过 {N}s 无数据」；不足 1 秒按毫秒说）。
export function streamTimeoutMessage(ms) {
  return `上游流超过 ${ms >= 1000 ? `${Math.round(ms / 1000)}s` : `${ms}ms`} 无数据`;
}

// SSE 单行上限：单帧只有 KB 级，超过说明上游异常，报错而不是继续占用内存。
const MAX_SSE_LINE = 4 * 1024 * 1024;

// 按网络 chunk 产出一批完整行（string[]）。按批产出而不是逐行：消费者可以
// 在一批内先处理完 finish 之后的数据（同一帧里的 usage 要取到），再结束。
// 超时：首块 firstByteMs，之后块间 idleMs，不设总超时。
// 只在等待上游读取时计时，消费者处理一批数据期间不计时。
// 超时抛 TimeoutError，不按正常结束处理。
export async function* sseLines(resp, { firstByteMs = 30000, idleMs = 180000 } = {}) {
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  let timer = null;
  let timedOut = null;
  let first = true;
  let batch = null;
  const arm = (ms) => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      timedOut = new Error(streamTimeoutMessage(ms));
      timedOut.name = "TimeoutError";
      // reader.cancel() 不会让挂起的 read() 拒绝（它正常返回 done），
      // 所以先记在 timedOut 上，等 read 返回后再抛。
      reader.cancel(timedOut).catch(() => {});
    }, ms);
    timer.unref?.();
  };
  try {
    for (;;) {
      if (batch) {
        const lines = batch;
        batch = null;
        yield lines; // 消费者处理这一批期间不计时
        continue;
      }
      arm(first ? firstByteMs : idleMs);
      first = false;
      let done = false;
      let value;
      try {
        ({ done, value } = await reader.read());
      } catch (e) {
        if (timedOut) throw timedOut;
        throw e;
      } finally {
        clearTimeout(timer);
      }
      if (timedOut) throw timedOut;
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      // 一次 split 完成切行，避免对超大块反复 slice
      const parts = buf.split("\n");
      buf = parts.pop() ?? "";
      if (buf.length > MAX_SSE_LINE) throw new Error("上游流单行过长");
      const lines = [];
      for (const line of parts) {
        if (line.length > MAX_SSE_LINE) throw new Error("上游流单行过长");
        lines.push(line.endsWith("\r") ? line.slice(0, -1) : line);
      }
      if (lines.length) batch = lines;
    }
    // 末尾没有换行的残行不处理
  } finally {
    clearTimeout(timer);
    // 没读完就离开（finish 后收尾 / 出错 / 调用方取消）：关掉上游连接
    reader.cancel().catch(() => {});
    try {
      reader.releaseLock();
    } catch {}
  }
}

// 发起流式请求：只给「建连 + 响应头」设超时（firstByteMs），响应头到达后解除。
// 之后由调用方检查 body 的活动性。不设总超时，长流不会被中断。
export async function openStream(url, init = {}, { firstByteMs = 30000 } = {}) {
  const ctrl = new AbortController();
  const signals = init.signal ? [init.signal, ctrl.signal] : [ctrl.signal];
  const timer = setTimeout(() => {
    const err = new Error("上游连接超时");
    err.name = "TimeoutError";
    try {
      ctrl.abort(err);
    } catch {}
  }, firstByteMs);
  timer.unref?.();
  try {
    return await fetch(url, { ...init, signal: AbortSignal.any(signals), redirect: "manual" });
  } finally {
    clearTimeout(timer);
  }
}

// 把上游 body 包成 pull 驱动的 ReadableStream，不解析内容（云伴 chat 按字节透传）。
// 只在等待上游时计时：首块 firstMs，之后块间 idleMs；下游暂停读取期间不计时。
// 下游取消时断开上游连接；超时让流以 TimeoutError 结束。
export function guardStream(body, { firstMs = 60000, idleMs = 180000 } = {}) {
  const reader = body.getReader();
  let timer = null;
  let failure = null;
  let first = true;
  const release = () => {
    try {
      reader.releaseLock();
    } catch {}
  };
  const arm = (ms) => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      failure = new Error(streamTimeoutMessage(ms));
      failure.name = "TimeoutError";
      reader.cancel(failure).catch(() => {}); // read() 会解析为 done，由 failure 抛出
    }, ms);
    timer.unref?.();
  };
  return new ReadableStream({
    async pull(controller) {
      if (failure) throw failure;
      arm(first ? firstMs : idleMs);
      let result;
      try {
        result = await reader.read();
      } catch (e) {
        if (failure) throw failure;
        throw e;
      } finally {
        clearTimeout(timer);
        first = false;
      }
      if (failure) {
        release();
        throw failure;
      }
      if (result.done) {
        release();
        controller.close();
        return;
      }
      controller.enqueue(result.value);
    },
    async cancel(reason) {
      clearTimeout(timer);
      if (failure) return;
      await reader.cancel(reason).catch(() => {});
      release();
    },
  });
}

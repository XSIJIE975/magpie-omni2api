// 本地页生命周期：绑定 127.0.0.1 随机端口、路由分发、TTL 到期或 abort 时关闭。
//
// Bun.serve 的处理函数运行在创建服务时的 AsyncLocalStorage 作用域里，因此：
//   - 每次 authorize() 起一个独立的服务，不在登录之间共享
//   - 凭据只在宿主调用的 callback() 里写入（账号作用域正确）
//   - 本地页的处理函数只调用上游、暂存结果
import { randomUUID } from "node:crypto";

export { randomUUID };

// 起一个本地页。onRequest(url, req) → Response | undefined（undefined = 404）。
// 返回 {port, url, stop}。TTL 到期或 signal abort 时自动关闭。
export function startPage({ onRequest, ttlMs = 10 * 60 * 1000, signal }) {
  let server = null;
  let stopped = false;
  let timer = null;
  const stop = () => {
    if (stopped) return;
    stopped = true;
    clearTimeout(timer);
    signal?.removeEventListener("abort", stop);
    try {
      server?.stop(true);
    } catch {}
  };
  if (signal) {
    if (signal.aborted) throw new Error("本地页：信号已中止");
    signal.addEventListener("abort", stop, { once: true });
  }
  timer = setTimeout(stop, ttlMs);
  timer.unref?.();
  server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0, // 随机可用端口
    maxRequestBodySize: 64 * 1024, // 登录表单只有几 KB
    // 默认 10s 会断开仍在等待上游的请求；登录链路要等上游响应，放宽到 120s
    idleTimeout: 120,
    async fetch(req) {
      try {
        const url = new URL(req.url);
        // req.url 的主机名来自 Host 头。只接受 127.0.0.1（127.1 等写法规范化后
        // 也是它），避免其它页面借 DNS rebinding 以同源身份访问本地页。
        if (url.hostname !== "127.0.0.1") return new Response("not found", { status: 404 });
        const resp = await onRequest(url, req);
        return resp ?? new Response("not found", { status: 404 });
      } catch (e) {
        return new Response(`本地页错误: ${escapeHtml(e?.message ?? e)}`, {
          status: 500,
          headers: { "content-type": "text/plain; charset=utf-8" },
        });
      }
    },
  });
  return { port: server.port, url: `http://127.0.0.1:${server.port}`, stop };
}

// 本地页统一响应头：不缓存、不发 Referer（页面 URL 可能带令牌）、不允许内嵌与外部资源。
const PAGE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

export function pageResponse(title, bodyHtml, { status = 200 } = {}) {
  return new Response(pageHtml(title, bodyHtml), {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "content-security-policy": PAGE_CSP,
    },
  });
}

// 简单 HTML 页壳（无外部资源；亮暗自适应）。
export function pageHtml(title, bodyHtml) {
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)}</title>
<style>body{font:15px/1.6 -apple-system,system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f6f6f4;color:#222}
@media(prefers-color-scheme:dark){body{background:#1c1c1c;color:#eee}}main{max-width:440px;padding:24px;width:100%;box-sizing:border-box}
h1{font-size:19px;margin:0 0 12px}label{display:block;margin:10px 0 4px;opacity:.8}input,select{width:100%;box-sizing:border-box;padding:8px 10px;font:inherit;border:1px solid #8884;border-radius:6px;background:transparent;color:inherit}
button{margin-top:14px;padding:8px 18px;font:inherit;border:0;border-radius:6px;background:#2a9d58;color:#fff;cursor:pointer}button:disabled{opacity:.5}button.alt{background:#666}
img.captcha{display:block;margin-top:8px;max-width:180px;border-radius:4px;border:1px solid #8884}
p{margin:6px 0;opacity:.75}.err{color:#d1453b;opacity:1}.ok{color:#2a9d58;opacity:1}code{background:#8882;padding:1px 5px;border-radius:4px}
.row{display:flex;gap:10px;align-items:center}</style>
<main>${bodyHtml}</main>`;
}

export function escapeHtml(s) {
  return String(s ?? "").replace(/[<>&"']/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;" })[c]);
}

// 读请求体为纯文本（form 或 JSON 都按文本拿，由调用方自行解析）。
// 登录表单只有几 KB：声明的 content-length 超过上限时返回空串，实际读到的文本
// 超过上限时截断到上限。
export async function readBody(req, { limit = 64 * 1024 } = {}) {
  const len = Number(req.headers.get("content-length") ?? 0);
  if (Number.isFinite(len) && len > limit) return "";
  try {
    const text = await req.text();
    return text.length > limit ? text.slice(0, limit) : text;
  } catch {
    return "";
  }
}

// form 或 JSON 双兼容取参。
export function parseParams(text) {
  const out = {};
  const t = String(text ?? "").trim();
  if (!t) return out;
  if (t.startsWith("{")) {
    try {
      return JSON.parse(t) ?? {};
    } catch {
      return {};
    }
  }
  for (const [k, v] of new URLSearchParams(t)) out[k] = v;
  return out;
}

// authorize 时记下账号键，callback 完成时核对作用域没变。
export function safeAccountKey(input, providerId) {
  try {
    return input?.magpie?.account?.(providerId) ?? "";
  } catch {
    return "";
  }
}

// 假上游（Bun.serve）：云伴 /auth/*、/me*、/v1/chat/completions，
// 灵码 /algo/api/v3/*（A 族）、/algo/api/v2/*（B 族）。
// 解码与签名校验是独立实现（直接用 node:crypto），不 import 插件代码。
import { createHash, createHmac } from "node:crypto";

const sha256hex = (d) => createHash("sha256").update(d).digest("hex");
const hmacSha256hex = (k, d) => createHmac("sha256", k).update(d).digest("hex");
const md5hex = (d) => createHash("md5").update(d).digest("hex");

// 独立的 customB64 解码（不 import 插件的 codec.mjs）
const LINGMA_ALPHABET = Buffer.from("_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!", "latin1");
function lingmaDecode(wire) {
  const bytes = Buffer.from(wire, "latin1").filter((b) => b !== 0x0d && b !== 0x0a);
  const n = bytes.length;
  const t = Math.floor(n / 3);
  const restored = Buffer.concat([bytes.subarray(n - t), bytes.subarray(t, n - t), bytes.subarray(0, t)]);
  const out = [];
  let acc = 0;
  let bits = 0;
  for (const ch of restored) {
    const v = LINGMA_ALPHABET.indexOf(ch);
    if (v < 0) continue;
    acc = ((acc << 6) | v) >>> 0;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

const json = (v, status = 200) =>
  new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });

const ENCODER = new TextEncoder();

// 按块吐 SSE：lines[i] 之间隔 delayMs；hang = 吐完后挂着不断开。
function sseStream(lines, { delayMs = 0, hang = false } = {}) {
  let i = 0;
  return new Response(
    new ReadableStream({
      async pull(controller) {
        if (i >= lines.length) {
          if (hang) return; // 再也不 enqueue / close：客户端只能靠超时或取消结束
          return controller.close();
        }
        if (i > 0 && delayMs) await Bun.sleep(delayMs);
        controller.enqueue(ENCODER.encode(lines[i++]));
      },
    }),
    { status: 200, headers: { "content-type": "text/event-stream" } },
  );
}

// 云伴 OpenAI 风格 SSE 的一行
const yunbanLine = (delta, finish = null) =>
  `data: ${JSON.stringify({ id: "cmpl-x", object: "chat.completion.chunk", created: 1, model: "m1", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
const YUNBAN_SSE = [
  yunbanLine({ role: "assistant", content: "" }),
  yunbanLine({ content: "你好" }),
  yunbanLine({}, "stop"),
  "data: [DONE]\n\n",
];
const yunbanSlow = (n) => [...Array.from({ length: n }, (_, i) => yunbanLine({ content: String(i) })), yunbanLine({}, "stop"), "data: [DONE]\n\n"];

// 灵码 agent SSE：内容帧 + 同帧 finish/usage（usage 必须取到）+ 控制帧。
const lingmaFrame = (body) => `data:${JSON.stringify({ statusCode: "OK", body: JSON.stringify(body) })}\n`;
const LINGMA_SSE = [
  lingmaFrame({ choices: [{ delta: { content: "你好" }, finish_reason: null }] }),
  lingmaFrame({ choices: [{ delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 } }),
  `data:${JSON.stringify({ firstTokenDuration: 43 })}\n`,
].join("\n");
const LINGMA_SLOW = (n) =>
  [
    ...Array.from({ length: n }, (_, i) => lingmaFrame({ choices: [{ delta: { content: String(i) }, finish_reason: null }] })),
    lingmaFrame({ choices: [{ delta: {}, finish_reason: "stop" }] }),
    `data:${JSON.stringify({ firstTokenDuration: 43 })}\n`,
  ].join("\n");

export function createMockUpstream() {
  // 行为开关：测试用例改这里来制造场景
  const state = {
    // 云伴
    captchaCode: "1234",
    smsRequired: false,
    smsCode: "5678",
    smsTicket: "tk1", // ≠ tk1 时挑战接口按「签名无效」拒绝（模拟 ticket 作废）
    badSignature: false,
    loginFailures: 0,
    loginEchoPassword: false, // true → 登录失败时在错误里回显提交的密码（验证脱敏）
    unauthorized: false, // 签名接口一律 401
    unauthorizedMessage: "", // ≠ "" → 401 用这句（可回显令牌，验证脱敏）
    yunbanChat: { mode: "normal", status: 0 }, // mode: normal | slow | hang；status ≠ 0 → 直接回该状态
    // 灵码
    lingmaOrgs: [{ orgId: "org-a", orgName: "组织A" }],
    lingmaStatusExpire: 1893456000000, // user/status 回的 expireTime（0 = 缺失）
    lingmaModelListStatus: 0, // ≠ 0 → model/list 回该状态
    lingmaExtraModels: [],
    lingmaRefreshEmpty: false, // true → refresh_token 回 200 但缺两个令牌（协议漂移）
    lingmaRefreshNoId: false, // true → refresh_token 回 200，带令牌但缺 id
    lingmaRefreshNoExpire: false, // true → refresh_token 不返回 expireTime（验证回退旧值）
    lingmaChat: { mode: "normal", status: 0 }, // mode: normal | slow | hang | json
    yunbanAccount: null, // ≠ null → /me/account 回这份权益
    aInner: {}, // 灵码 A 族接口解码后的内层 payload，按 path 存（断言字段集用）
    // 审计
    requests: [], // {path, headers, body}
    chatSignals: [], // chat 请求的 req.signal（观测客户端断开是否传到上游）
  };

  const count = (path) => state.requests.filter((r) => r.path === path).length;

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      const path = url.pathname;
      const bodyText = await req.text();
      state.requests.push({ path, headers: Object.fromEntries(req.headers.entries()), body: bodyText });
      if (path === "/v1/chat/completions" || path === "/algo/api/v2/service/pro/sse/agent_chat_generation") {
        state.chatSignals.push(req.signal);
      }

      // ---- 云伴签名接口：token + 签名校验 ----
      if (path === "/me" || path === "/me/models" || path === "/me/account" || path === "/v1/chat/completions") {
        const token = (req.headers.get("authorization") ?? "").replace(/^Bearer /, "");
        if (state.unauthorized || token !== "t1") {
          return json({ error: { code: "invalid_token", message: state.unauthorizedMessage || "token 不认识" } }, 401);
        }
        if (state.badSignature || !verifyYunbanSignature(req, bodyText, "sk1")) {
          return json({ error: { code: "invalid_signature", message: "签名校验失败" } }, 403);
        }
      }

      switch (path) {
        // ---------- 云伴登录面 ----------
        case "/auth/captcha":
          return json({ captchaId: "c1", image: "data:image/png;base64,iVBORw0KGgo=" });

        case "/auth/login":
        case "/auth/iam/login": {
          const b = JSON.parse(bodyText || "{}");
          const need = path === "/auth/login" ? ["username", "password", "captchaId", "captchaCode"] : ["username", "password", "captchaId", "captchaCode", "deviceId"];
          if (need.some((k) => b[k] === undefined) || Object.keys(b).length !== need.length) {
            return json({ error: { code: "invalid_request", message: "登录字段不符" } }, 400);
          }
          if (state.loginFailures > 0) {
            state.loginFailures--;
            return json({ error: { code: "captcha_invalid", message: "验证码错误" } }, 400);
          }
          if (b.captchaCode !== state.captchaCode) {
            return json({ error: { code: "captcha_invalid", message: "验证码错误" } }, 400);
          }
          if (state.loginEchoPassword) {
            return json({ error: { code: "invalid_request", message: `password ${b.password} rejected` } }, 400);
          }
          if (b.password === "wrong-pw") return json({ error: { code: "invalid_credentials", message: "账号或密码错误" } }, 401);
          if (state.smsRequired) return json({ challenge: { ticket: state.smsTicket, params: { mobile: "138****0000" } } });
          return json({ token: "t1", sessionKey: "sk1", expiresAt: "2030-01-01T00:00:00Z" });
        }

        case "/auth/iam/challenge": {
          const b = JSON.parse(bodyText || "{}");
          if (b.ticket !== "tk1") return json({ ErrorCode: "Signature Invalid", ErrorMessage: "请求签名无效或已过期，请重新登录" }, 400);
          if (b.code === state.smsCode) return json({ token: "t1", sessionKey: "sk1", expiresAt: "2030-01-01T00:00:00Z" });
          return json({ error: { code: "challenge_invalid", message: "短信码不对" } }, 400);
        }

        case "/auth/iam/resend":
          return json({ ok: true });

        // ---------- 云伴会话面 ----------
        case "/me":
          return json({
            token: "t1",
            expiresAt: "2030-01-01T00:00:00Z",
            identity: { issuer: "mock", tenantId: "t1", subject: "u1" },
            user: { userId: 101, name: "测试用户" },
          });

        case "/me/models":
          return json({ models: [{ id: "m1", label: "模型一", contextTokens: 128000, maxOutputTokens: 8192, thinking: true }] });

        case "/me/account":
          return json(state.yunbanAccount ?? {
            org: { id: "o1", name: "组织", unitType: "internal" },
            seat: { status: "active", validFrom: "2026-01-01", validTo: "2026-12-31", suspended: false },
            credits: { cycle: "2026-11", funded: 1000, consumed: 100, remaining: 900, overageMode: "block" },
          });

        case "/v1/chat/completions": {
          if (state.yunbanChat.status) {
            return json({ error: { code: state.yunbanChat.status === 429 ? "rate_limited" : "upstream_error", message: "上游拒绝" } }, state.yunbanChat.status);
          }
          const m = JSON.parse(bodyText || "{}").model;
          if (m === "m-hang") return sseStream([yunbanLine({ content: "先来一块" })], { hang: true });
          if (m === "m-slow") return sseStream(yunbanSlow(12), { delayMs: 80 });
          return sseStream(YUNBAN_SSE);
        }

        // ---------- 灵码（A 族：登录面） ----------
        case "/algo/api/v3/user/grantAuthInfos":
        case "/algo/api/v3/user/status":
        case "/algo/api/v3/user/refresh_token": {
          if (url.searchParams.get("Encode") !== "1") return json({ message: "缺 Encode=1" }, 400);
          const envelope = JSON.parse(lingmaDecode(bodyText).toString("utf8"));
          if (envelope.encodeVersion !== "1") return json({ message: "encodeVersion 必须为 1" }, 400);
          if (!req.headers.get("date") || !req.headers.get("signature") || req.headers.get("appcode") !== "cosy") {
            return json({ message: "缺 A 族三元组头" }, 400);
          }
          const inner = JSON.parse(envelope.payload);
          state.aInner[path] = inner;
          if (path === "/algo/api/v3/user/grantAuthInfos") return json(state.lingmaOrgs);
          if (path === "/algo/api/v3/user/refresh_token") {
            if (inner.needRefresh !== true) return json({ message: "needRefresh 必须为 true" }, 400);
            if (inner.refreshToken === "dead-rt") return json({ message: "refresh token 无效" }, 400);
            if (inner.refreshToken === "expired-rt") return json({ message: "登录已失效" }, 401);
            if (state.lingmaRefreshEmpty) return json({ id: "uid-1", name: "张三" });
            if (state.lingmaRefreshNoId) {
              return json({ securityOauthToken: "SECRET-TOKEN-LEAK", refreshToken: "SECRET-RT-LEAK", expireTime: 1893456000000 });
            }
            const body = {
              id: "uid-1",
              name: "张三",
              userType: "enterprise_standard",
              orgId: "org-a",
              orgName: "组织A",
              securityOauthToken: "sect-2",
              refreshToken: "rt-2",
            };
            return json(state.lingmaRefreshNoExpire ? body : { ...body, expireTime: 1893456000000 });
          }
          // user/status（回显所选组织；故意回一个不同的令牌，验证插件取的是回调的）
          return json({
            id: "uid-1",
            name: "张三",
            userType: "enterprise_standard",
            orgId: inner.orgId || "",
            orgName: inner.orgId ? (inner.orgId === "org-b" ? "组织B" : "组织A") : "",
            securityOauthToken: "sect-from-status-MUST-NOT-BE-USED",
            refreshToken: "rt-from-status",
            expireTime: state.lingmaStatusExpire,
          });
        }

        // ---------- 灵码（B 族：会话面） ----------
        case "/algo/api/v2/model/list": {
          if (!checkLingmaB(req, "")) return json({ message: "B 族头缺失" }, 400);
          if (state.lingmaModelListStatus) return json({ message: "目录暂不可用" }, state.lingmaModelListStatus);
          return json({
            chat: [{ key: "org_glm-5_x", display_name: "m", max_input_tokens: 200000 }, ...state.lingmaExtraModels],
            developer: [{ key: "org_glm-5_x", display_name: "dup" }],
            quest: [{ key: "automatic" }],
          });
        }

        case "/algo/api/v2/service/pro/sse/agent_chat_generation": {
          if (url.searchParams.get("Encode") !== "1" || url.searchParams.get("AgentId") !== "agent_common") {
            return json({ message: "缺查询参数" }, 400);
          }
          if (!checkLingmaB(req, bodyText)) return json({ message: "B 族头缺失" }, 400);
          // bodylength / bodyhash 与 wire 一致
          if (Number(req.headers.get("cosy-bodylength")) !== Buffer.byteLength(bodyText, "utf8")) {
            return json({ message: "bodylength 不符" }, 400);
          }
          if (req.headers.get("cosy-bodyhash") !== md5hex(bodyText)) return json({ message: "bodyhash 不符" }, 400);
          if (state.lingmaChat.status) return json({ message: "上游拒绝" }, state.lingmaChat.status);
          const agent = JSON.parse(lingmaDecode(bodyText).toString("utf8"));
          state.lastLingmaAgent = agent;
          const mode = state.lingmaChat.mode;
          if (mode === "json") return json({ code: "500", message: "执行失败" }); // 200 但不是流
          if (mode === "hang") return sseStream([lingmaFrame({ choices: [{ delta: { content: "先来一块" }, finish_reason: null }] })], { hang: true });
          if (mode === "slow") return sseStream(LINGMA_SLOW(12).split("\n").filter(Boolean).map((l) => l + "\n"), { delayMs: 80 });
          return sseStream(LINGMA_SSE.split("\n").map((l, i, a) => (i < a.length - 1 ? l + "\n" : l)));
        }

        default:
          return json({ error: { code: "not_found", message: "未知路径" } }, 404);
      }
    },
  });

  return {
    server,
    state,
    count,
    base: `http://127.0.0.1:${server.port}`,
    stop: () => server.stop(true),
  };
}

// 云伴签名校验（独立实现）。
function verifyYunbanSignature(req, bodyText, sessionKey) {
  const ts = req.headers.get("x-banban-timestamp") ?? "";
  const nonce = req.headers.get("x-banban-nonce") ?? "";
  const sig = req.headers.get("x-banban-signature") ?? "";
  if (!ts || !nonce || !sig) return false;
  const canonical = `POST\n${new URL(req.url).pathname}\n${sha256hex(Buffer.from(bodyText, "utf8"))}\n${ts}\n${nonce}`;
  return hmacSha256hex(sessionKey, canonical) === sig;
}

// 灵码 B 族 23 头在位 + 签名重算（独立实现）。
const LINGMA_B_HEADERS = [
  "authorization",
  "content-type",
  "accept",
  "accept-encoding",
  "cache-control",
  "cosy-key",
  "cosy-date",
  "cosy-bodyhash",
  "cosy-bodylength",
  "cosy-sigpath",
  "cosy-user",
  "cosy-organization-id",
  "cosy-organization-tags",
  "cosy-machineid",
  "cosy-machineos",
  "cosy-machinetoken",
  "cosy-machinetype",
  "cosy-clienttype",
  "cosy-clientip",
  "cosy-data-policy",
  "cosy-version",
  "login-version",
  "user-agent",
];
function checkLingmaB(req, wire) {
  for (const h of LINGMA_B_HEADERS) {
    // 三个头（organization-tags/machinetoken/machinetype）按规格就是空串：只判缺失
    if (req.headers.get(h) === null) return false;
  }
  const auth = req.headers.get("authorization") ?? "";
  if (!auth.startsWith("Bearer COSY.")) return false;
  const dot = auth.indexOf(".", "Bearer COSY.".length);
  if (dot < 0) return false;
  const payload = auth.slice("Bearer COSY.".length, dot);
  const sig = auth.slice(dot + 1);
  const expect = md5hex(
    `${payload}\n${req.headers.get("cosy-key") ?? ""}\n${req.headers.get("cosy-date") ?? ""}\n${wire}\n${req.headers.get("cosy-sigpath") ?? ""}`,
  );
  return expect === sig;
}

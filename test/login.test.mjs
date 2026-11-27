// 登录状态机与链路测试（假上游）：
// - 云伴：完整登录（验证码错误重试 / 页面补填 / 短信挑战 / 失败上限 / 接口防跨源）、
//   /me 合并与权益、chat 透传（长流不被掐、空闲超时、取消向上游传播）、续期节奏
// - 灵码：浏览器登录（单组织 / 多组织 / state 校验 / 令牌取回调）、chat 端到端
//   （B 族头、SSE 渲染、错误状态映射、空闲超时、模型目录缓存）、续期
// 登录结果都经 mock/host.mjs 的 hostCallback 按宿主的规则判定是否保存。
import { describe, test, expect, beforeEach, afterAll } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMockUpstream } from "./mock/upstream.mjs";
import { makeStubHost, makeCaller, hostCallback, until } from "./mock/host.mjs";
import { yunbanPlugin, YUNBAN_ID } from "../yunban/index.mjs";
import { beginLogin as yunbanBegin, parseLoginPayload, classifyLoginError } from "../yunban/login.mjs";
import {
  mergeMe,
  accountIdOf,
  parseEntitlement,
  entitlementUsable,
  usageFromEntitlement,
  seatProblem,
  nextExpiry,
} from "../yunban/session.mjs";
import { lingmaPlugin, LINGMA_ID } from "../lingma/index.mjs";
import { beginLogin as lingmaBegin, callbackBlocks } from "../lingma/login.mjs";
import { parseCallbackToken } from "../lingma/upstream.mjs";
import { encode } from "../lingma/codec.mjs";

// 测试专用的临时目录（机器码 / 设备码缓存不碰真实的那份）
const scratch = mkdtempSync(join(tmpdir(), "magpie-omni2api-test-"));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const PASSWORD = "S3cret-PW-value!";
const MSGS = [{ role: "user", content: "你好" }];

// SSE 文本 → 每块的类别序列
const shapesOf = (text) =>
  text
    .split("\n\n")
    .filter((l) => l.trim())
    .map((l) => {
      if (l.trim() === "data: [DONE]") return "DONE";
      const v = JSON.parse(l.slice(6));
      if (v.error) return "error";
      if (v.usage) return "usage";
      const c = v.choices?.[0] ?? {};
      if (c.delta?.role) return "role";
      if ("content" in (c.delta ?? {})) return "content";
      if ("reasoning_content" in (c.delta ?? {})) return "reasoning";
      if ("tool_calls" in (c.delta ?? {})) return "tool_calls";
      if (c.finish_reason) return `finish:${c.finish_reason}`;
      return "other";
    });

// 已保存形状的凭据（宿主保存之后的记录）
const yunbanStored = () => ({
  type: "oauth",
  refresh: "sk1",
  access: "t1",
  expires: nextExpiry(),
  accountId: "101",
  token: "t1",
  sessionKey: "sk1",
  expiresAt: "2030-01-01T00:00:00Z",
  deviceId: "d".repeat(32),
  loginMode: "local",
  username: "u1",
  identity: { issuer: "mock", tenantId: "t1", subject: "u1" },
  user: { userId: 101, name: "测试用户" },
});
const lingmaStored = () => ({
  type: "oauth",
  refresh: "rt-1",
  access: "sect-1",
  expires: 1893456000000,
  accountId: "uid-1|org-a",
  uid: "uid-1",
  name: "张三",
  userType: "enterprise_standard",
  organizationId: "org-a",
  organizationName: "组织A",
  key: "k",
  encryptUserInfo: "eui",
  machineId: "0f0e0d0c-0b0a-4a49-8a79-6b5c4d3e2f10",
  refreshToken: "rt-1",
  securityOauthToken: "sect-1",
  expireTimeMs: 1893456000000,
});

// 距 now+30min 的分钟数（续期节奏断言用）
const minutesAway = (ms) => (ms - Date.now()) / 60000;

// ---------------------------------------------------------------- 云伴登录

async function openYunban(mock, inputs) {
  const stub = makeStubHost({ providerId: YUNBAN_ID });
  const ctrl = new AbortController();
  const login = await yunbanBegin(inputs, {
    input: stub.input,
    client: stub.input.client,
    base: mock.base,
    providerId: YUNBAN_ID,
    signal: ctrl.signal,
    deviceFile: join(scratch, "yunban-device.json"),
  });
  const call = (path, body, headers = {}) =>
    fetch(`${login._page.url}${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    }).then(async (r) => ({ status: r.status, body: await r.json() }));
  return { login, stub, ctrl, call, api: (path, body) => call(path, body, { "x-login-token": login._token }) };
}
const FULL = { loginMode: "local", username: "u1", password: PASSWORD };
const ORG_B = { orgId: "org-b", orgName: "组织B" };

describe("云伴登录：parseLoginPayload", () => {
  test("challenge:null 视为无挑战", () => {
    expect(parseLoginPayload({ challenge: null, token: "t", sessionKey: "k" })).toEqual({
      session: { token: "t", sessionKey: "k", expiresAt: "" },
    });
  });
  test("challenge 对象（含空对象）是挑战，取 ticket 与 mobile", () => {
    expect(parseLoginPayload({ challenge: { ticket: "tk", params: { mobile: "138" } } })).toEqual({ sms: { ticket: "tk", mobile: "138" } });
    expect(parseLoginPayload({ challenge: {} }).fatal).toContain("ticket");
  });
  test("缺 token/sessionKey 报错", () => {
    expect(parseLoginPayload({ token: "t" }).fatal).toContain("token/sessionKey");
    expect(parseLoginPayload({ sessionKey: "k" }).fatal).toContain("token/sessionKey");
  });
});

describe("云伴登录：classifyLoginError", () => {
  test("验证码类换图重试", () => {
    expect(classifyLoginError("captcha_invalid", "x").retryCaptcha).toBeTruthy();
    expect(classifyLoginError("whatever", "验证码不对").retryCaptcha).toBeTruthy();
  });
  test("invalid_credentials → 账号或密码不对；upstream_unreachable → 上游统一认证暂不可达（都是 fatal）", () => {
    expect(classifyLoginError("invalid_credentials", "x").fatal).toContain("账号或密码");
    expect(classifyLoginError("upstream_unreachable", "x").fatal).toContain("不可达");
  });
  test("iam 终态码不可重试", () => {
    for (const code of ["account_locked", "password_expired", "sms_unavailable", "account_disabled", "not_found"]) {
      expect(classifyLoginError(code, "x").fatal).toBeTruthy();
    }
  });
});

describe("云伴登录：完整流程（假上游）", () => {
  let mock;
  beforeEach(() => {
    mock?.stop();
    mock = createMockUpstream();
  });

  test("local：验证码错一次后成功；宿主判定为成功并落盘；密码不进 HTML、不落盘、不进日志", async () => {
    const { login, stub, api } = await openYunban(mock, FULL);
    // token 只在 URL fragment 里：页面 HTML 不带 token（别的本机进程拿不到）
    expect(login.url).toContain(`#t=${login._token}`);
    const page = await fetch(`${login._page.url}/`).then((r) => r.text());
    expect(page).not.toContain(PASSWORD); // 密码不渲染进页面
    expect(page).not.toContain(login._token);
    expect(page).toContain("x-login-token");
    expect(await api("/state")).toMatchObject({ status: 200, body: { stage: "captcha", needMode: false, needUser: false, needPass: false } });
    const cap = await api("/captcha");
    expect(cap.body.captchaId).toBe("c1");
    expect(cap.body.image.startsWith("data:image/png;base64,")).toBe(true);

    const bad = await api("/submit", { captchaId: "c1", captchaCode: "0000" });
    expect(bad.body.stage).toBe("captcha");
    expect(bad.body.error).toContain("验证码");
    const ok = await api("/submit", { captchaId: "c1", captchaCode: "1234" });
    expect(ok.body.stage).toBe("done");

    // 宿主的规则：type 必须是 "success"，且有可保存的 refresh / access
    const { ok: signedIn, stored } = await hostCallback(login);
    expect(signedIn).toBe(true);
    expect(stored).toMatchObject({
      type: "oauth",
      refresh: "sk1",
      access: "t1",
      token: "t1",
      sessionKey: "sk1",
      loginMode: "local",
      username: "u1",
      expiresAt: "2030-01-01T00:00:00Z",
      accountId: "101", // /me 的 user.userId
      user: { userId: 101, name: "测试用户" },
      identity: { issuer: "mock", tenantId: "t1", subject: "u1" },
    });
    expect(stored.deviceId).toMatch(/^[0-9a-f]{32}$/);
    // expires = 现在 + 30 分钟（滑动续期节奏），不取上游的 2030
    expect(minutesAway(stored.expires)).toBeGreaterThan(29);
    expect(minutesAway(stored.expires)).toBeLessThanOrEqual(30);
    // 不存密码
    expect(JSON.stringify(stored)).not.toContain(PASSWORD);
    expect(stored).not.toHaveProperty("password");
    // 也不进日志（mock 宿主收集了 client.app.log）
    expect(stub.logs.map((l) => l.message).join("\n")).not.toContain(PASSWORD);
    // 登录请求体：local 模式恰好四个字段，密码原样（不 trim）
    const req = JSON.parse(mock.state.requests.find((r) => r.path === "/auth/login").body);
    expect(Object.keys(req).sort()).toEqual(["captchaCode", "captchaId", "password", "username"]);
    expect(req.password).toBe(PASSWORD);
  });

  test("宿主没问 prompts：页面上补填登录方式 / 账号 / 密码也能完成（iam 带 deviceId）", async () => {
    const { login, api } = await openYunban(mock, {});
    expect(await api("/state")).toMatchObject({ body: { stage: "captcha", needMode: true, needUser: true, needPass: true } });
    const cap = await api("/captcha");
    const out = await api("/submit", { loginMode: "sso", username: "  u1  ", password: `  ${PASSWORD}  `, captchaId: cap.body.captchaId, captchaCode: "1234" });
    expect(out.body.stage).toBe("done");
    const req = JSON.parse(mock.state.requests.find((r) => r.path === "/auth/iam/login").body);
    expect(req.username).toBe("u1"); // trim
    expect(req.password).toBe(`  ${PASSWORD}  `); // 不 trim
    expect(req.deviceId).toMatch(/^[0-9a-f]{32}$/);
    const { ok, stored } = await hostCallback(login);
    expect(ok).toBe(true);
    expect(stored.loginMode).toBe("sso");
    expect(JSON.stringify(stored)).not.toContain(PASSWORD);
  });

  test("deviceId 安装级稳定：两次登录同一个", async () => {
    const a = await openYunban(mock, FULL);
    await a.api("/submit", { captchaId: "c1", captchaCode: "1234" });
    const { stored: s1 } = await hostCallback(a.login);
    const b = await openYunban(mock, FULL);
    await b.api("/submit", { captchaId: "c1", captchaCode: "1234" });
    const { stored: s2 } = await hostCallback(b.login);
    expect(s1.deviceId).toMatch(/^[0-9a-f]{32}$/);
    expect(s2.deviceId).toBe(s1.deviceId);
  });

  test("sso：短信挑战；重发最多 3 次；错码一次即作废；刷新页面不丢阶段", async () => {
    mock.state.smsRequired = true;
    const { login, api } = await openYunban(mock, { ...FULL, loginMode: "sso" });
    await api("/captcha");
    const first = await api("/submit", { captchaId: "c1", captchaCode: "1234" });
    expect(first.body).toMatchObject({ stage: "sms", mobile: "138****0000" });
    expect(await api("/state")).toMatchObject({ body: { stage: "sms", mobile: "138****0000" } });
    // 重发是一等接口，最多 3 次
    expect((await api("/resend", {})).body.limit).toBe(false);
    expect((await api("/resend", {})).body.limit).toBe(false);
    expect((await api("/resend", {})).body.limit).toBe(true);
    expect((await api("/resend", {})).body.error).toContain("上限");
    // 短信码错误后挑战作废：回到验证码表单重新发起
    const wrong = await api("/sms", { code: "0000" });
    expect(wrong.body.stage).toBe("captcha");
    expect(wrong.body.error).toContain("已作废");
    expect(await api("/state")).toMatchObject({ body: { stage: "captcha" } });
    // 重新发起 → 再进短信阶段 → 正确短信码
    expect((await api("/submit", { captchaId: "c1", captchaCode: "1234" })).body.stage).toBe("sms");
    const ok = await api("/sms", { code: "5678" });
    expect(ok.body.stage).toBe("done");
    const { ok: signedIn, stored } = await hostCallback(login);
    expect(signedIn).toBe(true);
    expect(stored.loginMode).toBe("sso");
    expect(stored.access).toBe("t1");
    const req = JSON.parse(mock.state.requests.find((r) => r.path === "/auth/iam/challenge" && JSON.parse(r.body).code === "5678").body);
    expect(Object.keys(req).sort()).toEqual(["code", "deviceId", "password", "ticket", "username"]);
    expect(JSON.parse(mock.state.requests.find((r) => r.path === "/auth/iam/resend").body)).toEqual({ ticket: "tk1" });
  });

  test("短信挑战的 ticket 已失效（signature_invalid）→ 同样回验证码表单重新发起", async () => {
    mock.state.smsRequired = true;
    mock.state.smsTicket = "tk-old";
    const { login, api } = await openYunban(mock, { ...FULL, loginMode: "sso" });
    expect((await api("/submit", { captchaId: "c1", captchaCode: "1234" })).body.stage).toBe("sms");
    const gone = await api("/sms", { code: "5678" });
    expect(gone.body.stage).toBe("captcha");
    expect(gone.body.error).toContain("已作废");
    // 登录流程未结束：可以重新发起
    expect((await api("/submit", { captchaId: "c1", captchaCode: "1234" })).body.stage).toBe("sms");
    expect(login._state.stage).toBe("sms");
  });

  test("验证码连续 3 次失败 → failed；宿主判定为失败并给出原因", async () => {
    const { login, api } = await openYunban(mock, FULL);
    let last;
    for (let i = 0; i < 3; i++) last = await api("/submit", { captchaId: "c1", captchaCode: "0000" });
    expect(last.body.stage).toBe("failed");
    expect(last.body.error).toContain("验证码连续 3 次");
    expect(await api("/state")).toMatchObject({ body: { stage: "failed" } });
    const { ok, error } = await hostCallback(login);
    expect(ok).toBe(false);
    expect(error).toContain("重新发起登录");
  });

  test("账号或密码不对 → failed", async () => {
    const { login, api } = await openYunban(mock, { ...FULL, password: "wrong-pw" });
    const out = await api("/submit", { captchaId: "c1", captchaCode: "1234" });
    expect(out.body.stage).toBe("failed");
    const { ok, error } = await hostCallback(login);
    expect(ok).toBe(false);
    expect(error).toContain("账号或密码不对");
  });

  test("上游错误回显密码：本地页 / state / 日志都不出现密码", async () => {
    mock.state.loginEchoPassword = true;
    const { login, stub, api } = await openYunban(mock, FULL);
    const out = await api("/submit", { captchaId: "c1", captchaCode: "1234" });
    expect(out.body.stage).toBe("failed");
    expect(JSON.stringify(out.body)).not.toContain(PASSWORD);
    const st = await api("/state");
    expect(JSON.stringify(st.body)).not.toContain(PASSWORD);
    expect(stub.logs.map((l) => l.message).join("\n")).not.toContain(PASSWORD);
    const html = await fetch(`${login._page.url}/`).then((r) => r.text());
    expect(html).not.toContain(PASSWORD);
  });

  test("页面选的 SSO 在挑战作废重绘后保持；验证码失败计数按新挑战重置", async () => {
    mock.state.smsRequired = true;
    mock.state.smsTicket = "tk-old"; // 挑战 ticket 不被接受（模拟作废）
    const { api, login } = await openYunban(mock, {}); // 宿主没问登录方式
    expect((await api("/state")).body.needMode).toBe(true);
    // 验证码错一次：失败计数为 1
    const wrong = await api("/submit", { loginMode: "sso", username: "u1", password: PASSWORD, captchaId: "c1", captchaCode: "0000" });
    expect(wrong.body.stage).toBe("captcha");
    expect(login._state.captchaFails).toBe(1);
    const first = await api("/submit", { loginMode: "sso", username: "u1", password: PASSWORD, captchaId: "c1", captchaCode: "1234" });
    expect(first.body.stage).toBe("sms");
    expect(login._state.captchaFails).toBe(0); // 进入短信阶段：计数重置
    expect(first.body.needMode).toBe(false); // 选过就不回退
    const gone = await api("/sms", { code: "5678" });
    expect(gone.body.stage).toBe("captcha");
    expect(gone.body.mode).toBe("sso"); // 重绘后仍是 SSO
    mock.state.smsTicket = "tk1";
    const again = await api("/submit", { captchaId: "c1", captchaCode: "1234" });
    expect(again.body.stage).toBe("sms");
    // 三次都走 SSO 登录端点（含验证码错误那次），不是 local
    expect(mock.state.requests.filter((r) => r.path === "/auth/iam/login")).toHaveLength(3);
    expect(mock.state.requests.filter((r) => r.path === "/auth/login")).toHaveLength(0);
  });

  test("登录接口只认本页令牌：无令牌 / 错令牌一律 403，打不到上游", async () => {
    const { call } = await openYunban(mock, FULL);
    expect((await call("/state")).status).toBe(403);
    expect((await call("/captcha")).status).toBe(403);
    expect((await call("/submit", { captchaCode: "0000" }, { "x-login-token": "wrong" })).status).toBe(403);
    expect((await call("/sms", { code: "1" })).status).toBe(403);
    expect((await call("/resend", {})).status).toBe(403);
    expect(mock.state.requests.filter((r) => r.path.startsWith("/auth/"))).toHaveLength(0);
  });

  test("宿主取消登录（callback 的 signal 中止）→ 登录以失败收尾", async () => {
    const { login } = await openYunban(mock, FULL);
    const ctrl = new AbortController();
    const pending = hostCallback(login, { signal: ctrl.signal });
    ctrl.abort();
    const { ok, error } = await pending;
    expect(ok).toBe(false);
    expect(error).toBe("登录已取消");
    // 本地页也关掉：端口不再应答
    await expect(fetch(`${login._page.url}/state`).then((r) => r.status)).rejects.toBeTruthy();
  });
});

// ---------------------------------------------------------------- 云伴会话

describe("云伴会话：/me 合并与权益", () => {
  test("mergeMe：token/身份/用户覆盖，sessionKey 与 expires 不动", () => {
    const auth = { ...yunbanStored(), access: "old", token: "old", identity: {}, user: { userId: 0, name: "" } };
    const next = mergeMe(auth, {
      token: "new",
      expiresAt: "2031-01-01T00:00:00Z",
      identity: { issuer: "i", tenantId: "t", subject: "s" },
      user: { userId: 7, name: "张三" },
    });
    expect(next.token).toBe("new");
    expect(next.access).toBe("new");
    expect(next.sessionKey).toBe("sk1");
    expect(next.refresh).toBe("sk1");
    expect(next.expires).toBe(auth.expires);
    expect(next.expiresAt).toBe("2031-01-01T00:00:00Z");
    expect(next.identity).toEqual({ issuer: "i", tenantId: "t", subject: "s" });
    expect(next.user).toEqual({ userId: 7, name: "张三" });
    // 空值不覆盖
    const kept = mergeMe(next, { token: "", expiresAt: "", user: { userId: 0, name: "" } });
    expect(kept.token).toBe("new");
    expect(kept.user).toEqual({ userId: 7, name: "张三" });
  });

  test("accountId：userId → name → username", () => {
    expect(accountIdOf({ user: { userId: 5, name: "n" }, username: "u" })).toBe("5");
    expect(accountIdOf({ user: { userId: 0, name: "n" }, username: "u" })).toBe("n");
    expect(accountIdOf({ user: { userId: 0, name: "" }, username: "u" })).toBe("u");
  });

  test("权益判定黑名单", () => {
    const e = parseEntitlement;
    expect(entitlementUsable(e({ seat: { status: "active", suspended: false }, credits: { remaining: 900, overageMode: "block" } }))).toBe(true);
    expect(entitlementUsable(e({ seat: { status: "expiring" }, credits: { remaining: 10 } }))).toBe(true); // expiring 仍可用
    expect(entitlementUsable(e({ seat: { status: "expired" } }))).toBe(false);
    expect(entitlementUsable(e({ seat: { status: "suspended" } }))).toBe(false);
    expect(entitlementUsable(e({ seat: { status: "not_issued" } }))).toBe(false);
    expect(entitlementUsable(e({ seat: { status: "active", suspended: true } }))).toBe(false);
    expect(entitlementUsable(e({ credits: { remaining: 0, overageMode: "block" } }))).toBe(false);
    expect(entitlementUsable(e({ credits: { remaining: -5 } }))).toBe(false);
    expect(entitlementUsable(e({ credits: { remaining: 0, overageMode: "bill" } }))).toBe(true);
    expect(entitlementUsable(e({ seat: { status: "ACTIVE" } }))).toBe(true); // 区分大小写，未知放行
    expect(entitlementUsable(e({}))).toBe(true); // 解析失败整体放行
    expect(seatProblem({ status: "expired" })).toBe("席位已过期");
    expect(seatProblem({ status: "active" })).toBe("");
  });

  test("usage 映射：used 是百分比，amount/limit 是计数；席位旁注；plan=org.name", () => {
    const ent = parseEntitlement({
      org: { id: "o1", name: "组织" },
      seat: { status: "active", validTo: "2026-12-31" },
      credits: { cycle: "2026-11", funded: 1000, consumed: 100, remaining: 900, overageMode: "block" },
    });
    const u = usageFromEntitlement(ent);
    expect(u.plan).toBe("组织");
    expect(u.windows.find((w) => w.name === "积分")).toEqual({ name: "积分", amount: 100, limit: 1000, unit: "credits", used: 10 });
    const seat = u.windows.find((w) => w.name === "席位");
    expect(seat.aside).toBe(true);
    expect(seat.display).toContain("2026-12-31");
    expect(seat.used).toBeUndefined();
    // 超额：百分比不封顶（宿主支持 used > 100 表示超额）；funded 为 0 时不报 used（「没说」不是 0%）
    expect(usageFromEntitlement(parseEntitlement({ credits: { funded: 100, consumed: 250 } })).windows[0].used).toBe(250);
    expect(usageFromEntitlement(parseEntitlement({ credits: { funded: 0, consumed: 5 } })).windows[0].used).toBeUndefined();
  });
});

// ---------------------------------------------------------------- 云伴 chat / hooks

describe("云伴 chat 透传与 hooks（假上游）", () => {
  let mock;
  beforeEach(() => {
    mock?.stop();
    mock = createMockUpstream();
  });
  const fast = (stub) => yunbanPlugin(stub.input, { yunbanBase: mock.base, firstByteMs: 150, idleMs: 400 });

  test("chat：签名通过、SSE 原样返回、指纹头；成功响应不带 X-Magpie-Sign-In", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    const caller = await makeCaller(await fast(stub), { auth: yunbanStored() });
    const resp = await caller.chat({ model: "m1", stream: true, messages: MSGS });
    expect(resp.status).toBe(200);
    // 2xx 不带该头：宿主据此清除账号的失效标记；带 kept 不做处理
    expect(resp.headers.get("x-magpie-sign-in")).toBeNull();
    expect(resp.headers.get("content-type")).toContain("text/event-stream");
    const text = await resp.text();
    expect(text).toContain('"content":"你好"');
    expect(text.trimEnd().endsWith("data: [DONE]")).toBe(true);
    const req = mock.state.requests.find((r) => r.path === "/v1/chat/completions");
    expect(req.headers["authorization"]).toBe("Bearer t1");
    expect(req.headers["x-banban-signature"]).toMatch(/^[0-9a-f]{64}$/);
    expect(req.headers["x-banban-timestamp"]).toMatch(/^\d{13}$/);
    expect(req.headers["x-banban-nonce"]).toMatch(/^[0-9a-f-]{36}$/);
    expect(req.headers["user-agent"]).toBe("OpenAI/JS 4.104.0");
    expect(req.headers["x-stainless-package-version"]).toBe("4.104.0");
    expect(req.headers["x-stainless-timeout"]).toBe("300");
    // 字节级透传
    expect(req.body).toBe(JSON.stringify({ model: "m1", stream: true, messages: MSGS }));
  });

  test("长流不被掐：首字节超时 150ms，流持续近 1 秒仍完整到达", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    // idle 放宽到 2s，避免较慢的机器上块间超时误报
    const caller = await makeCaller(await yunbanPlugin(stub.input, { yunbanBase: mock.base, firstByteMs: 150, idleMs: 2000 }), { auth: yunbanStored() });
    const resp = await caller.chat({ model: "m-slow", stream: true, messages: MSGS });
    const text = await resp.text();
    expect((text.match(/"content":"\d+"/g) ?? []).length).toBe(12);
    expect(text.trimEnd().endsWith("data: [DONE]")).toBe(true);
  });

  test("空闲超时：上游吐一块后挂住 → 流以超时报错，不是悄悄结束", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    const caller = await makeCaller(await fast(stub), { auth: yunbanStored() });
    const resp = await caller.chat({ model: "m-hang", stream: true, messages: MSGS });
    const err = await resp.text().then(
      () => null,
      (e) => e,
    );
    expect(err?.message).toMatch(/上游流超过 \d+ms 无数据/);
  });

  test("下游取消 → 上游连接立刻断开（不等空闲超时）", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    const caller = await makeCaller(await yunbanPlugin(stub.input, { yunbanBase: mock.base, idleMs: 60000 }), { auth: yunbanStored() });
    const resp = await caller.chat({ model: "m-hang", stream: true, messages: MSGS });
    const reader = resp.body.getReader();
    await reader.read();
    const upstream = mock.state.chatSignals.at(-1);
    expect(upstream.aborted).toBe(false);
    await reader.cancel("client gone");
    expect(await until(() => upstream.aborted)).toBe(true);
  });

  test("宿主 abort signal → 上游连接断开", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    const caller = await makeCaller(await yunbanPlugin(stub.input, { yunbanBase: mock.base, idleMs: 60000 }), { auth: yunbanStored() });
    const ctrl = new AbortController();
    const resp = await caller.chat({ model: "m-hang", stream: true, messages: MSGS }, { signal: ctrl.signal });
    await resp.body.getReader().read();
    const upstream = mock.state.chatSignals.at(-1);
    ctrl.abort();
    expect(await until(() => upstream.aborted)).toBe(true);
  });

  test("上游状态映射：429→429 kept；500→502；400→400；401→401 expired；403→400；302→502；文案是上游原文", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    const caller = await makeCaller(await fast(stub), { auth: yunbanStored() });
    for (const [up, want, signIn] of [
      [429, 429, "kept"],
      [500, 502, "kept"],
      [400, 400, "kept"],
      [401, 401, "expired"],
      [403, 400, "kept"],
      [302, 502, "kept"],
    ]) {
      mock.state.yunbanChat.status = up;
      const resp = await caller.chat({ model: "m1", messages: MSGS });
      expect(resp.status).toBe(want);
      expect(resp.headers.get("x-magpie-sign-in")).toBe(signIn);
      const body = await resp.json();
      expect(body.error.message).toContain("上游拒绝");
      if (signIn === "expired") expect(body.error.message).toContain("重新登录");
    }
    mock.state.yunbanChat.status = 0;
  });

  test("上游不可达 → 502 kept，文案含私有网络提示且不含登录类词", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    const caller = await makeCaller(await yunbanPlugin(stub.input, { yunbanBase: "http://127.0.0.1:9" }), { auth: yunbanStored() });
    const resp = await caller.chat({ model: "m1", messages: MSGS });
    expect(resp.status).toBe(502);
    expect(resp.headers.get("x-magpie-sign-in")).toBe("kept");
    const msg = (await resp.json()).error.message;
    expect(msg).toContain("http://127.0.0.1:9");
    expect(msg).toContain("私有网络");
    expect(msg).not.toMatch(/token|session|登录|过期/i);
  });

  test("非 chat 请求 → 400；未登录 → 401 expired", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    const hooks = await fast(stub);
    const caller = await makeCaller(hooks, { auth: yunbanStored() });
    const emb = await caller.embeddings({ input: "x" });
    expect(emb.status).toBe(400);
    expect((await emb.json()).error.message).toBe("只提供 chat completions");
    expect(emb.headers.get("x-magpie-sign-in")).toBe("kept");
    const anon = await makeCaller(hooks, { auth: undefined });
    const unauth = await anon.chat({ model: "m1", messages: MSGS });
    expect(unauth.status).toBe(401);
    expect(unauth.headers.get("x-magpie-sign-in")).toBe("expired");
  });

  test("provider.models：/me/models → 模型表（与宿主给的列表合并）；401 抛 expired；其余保留旧列表", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    const hooks = await fast(stub);
    const out = await hooks.provider.models({ models: { old: { id: "old" } } }, { auth: yunbanStored() });
    // 上游目录与 config 里补充的模型都保留（钩子的返回值整体替换宿主列表）
    expect(Object.keys(out).sort()).toEqual(["m1", "old"]);
    expect(out.m1).toMatchObject({ id: "m1", name: "模型一", api: { id: "m1", npm: "@ai-sdk/openai-compatible" }, limit: { context: 128000, output: 8192 } });
    expect(out.m1.capabilities.reasoning).toBe(true);
    mock.state.unauthorized = true;
    mock.state.unauthorizedMessage = "invalid token Bearer SECRET-TOKEN-abc";
    // 401 的错误文本会进入宿主日志：先脱敏
    const leak = await hooks.provider.models({ models: {} }, { auth: yunbanStored() }).catch((e) => e);
    expect(leak).toMatchObject({ signIn: "expired" });
    expect(leak.message).not.toContain("SECRET-TOKEN-abc");
    mock.state.unauthorized = false;
    mock.state.unauthorizedMessage = "";
    mock.state.badSignature = true; // 403：不是登录失效
    const kept = await hooks.provider.models({ models: { old: { id: "old" } } }, { auth: yunbanStored() });
    expect(Object.keys(kept)).toEqual(["old"]);
  });

  test("refresh：/me 滑动续期，expires 每次重置为 now+30min，sessionKey 不动", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    const hooks = await fast(stub);
    const stale = { ...yunbanStored(), expires: Date.now() + 60_000, user: { userId: 0, name: "" } };
    const next = await hooks.auth.refresh(stale);
    expect(next.access).toBe("t1");
    expect(next.token).toBe("t1");
    expect(next.sessionKey).toBe("sk1");
    expect(next.refresh).toBe("sk1");
    expect(next.user.userId).toBe(101);
    expect(minutesAway(next.expires)).toBeGreaterThan(29); // 不取上游的 2030
    mock.state.unauthorized = true;
    await expect(hooks.auth.refresh(stale)).rejects.toMatchObject({ signIn: "expired" });
    // 网络故障：不标记账号
    mock.state.unauthorized = false;
    const offline = await yunbanPlugin(stub.input, { yunbanBase: "http://127.0.0.1:9" });
    const err = await offline.auth.refresh(stale).catch((e) => e);
    expect(err.signIn).toBe("kept");
    expect(err.message).not.toMatch(/token|session|登录|过期/i);
  });

  test("usage：积分百分比 + 席位旁注，不带 signIn、不报 error；401 → expired", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    const hooks = await fast(stub);
    const u = await hooks.auth.usage(async () => yunbanStored());
    // 读取成功不带 signIn：宿主据此清除账号的失效标记
    expect(u.signIn).toBeUndefined();
    expect(u.plan).toBe("组织");
    expect(u.error).toBeUndefined();
    expect(u.windows.find((w) => w.name === "积分")).toMatchObject({ used: 10, amount: 100, limit: 1000, unit: "credits" });
    mock.state.unauthorized = true;
    expect(await hooks.auth.usage(async () => yunbanStored())).toEqual({ error: "需要重新登录", signIn: "expired" });
  });

  test("usage：席位停用 / 额度用尽 → 数字照给，另用 error 说明该账号不可用", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    const hooks = await fast(stub);
    const read = () => hooks.auth.usage(async () => yunbanStored());
    const account = {
      org: { name: "组织" },
      seat: { status: "active" },
      credits: { funded: 100, consumed: 100, remaining: 0, overageMode: "block" },
    };
    mock.state.yunbanAccount = { ...account, seat: { status: "expired" } };
    const seat = await read();
    expect(seat.error).toContain("席位已过期");
    expect(seat.windows.find((w) => w.name === "积分").used).toBe(100);
    mock.state.yunbanAccount = account;
    expect((await read()).error).toBe("当期额度已用尽，该账号无法发起请求");
    // 用尽但允许超额计费：仍可用，不报 error
    mock.state.yunbanAccount = { ...account, credits: { ...account.credits, overageMode: "bill" } };
    expect((await read()).error).toBeUndefined();
  });

  test("登录方式的 prompts：密码用 password 型（不回显）", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    const hooks = await fast(stub);
    const [method] = hooks.auth.methods;
    expect(method.type).toBe("oauth");
    expect(method.prompts.map((p) => [p.type, p.key])).toEqual([
      ["select", "loginMode"],
      ["text", "username"],
      ["password", "password"],
    ]);
    expect(method.prompts[0].options.map((o) => o.value)).toEqual(["local", "sso"]);
    expect(method.prompts[1].validate("")).toBe("请填写账号");
    expect(method.prompts[1].validate("u1")).toBeNull();
  });

  test("基址来源：options 优先于环境变量 YUNBAN_BASE；末尾斜杠剥掉", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    process.env.YUNBAN_BASE = "https://env.example.com/";
    try {
      const fromEnv = await yunbanPlugin(stub.input, {});
      const cfgEnv = {};
      await fromEnv.config(cfgEnv);
      expect(cfgEnv.provider[YUNBAN_ID].api).toBe("https://env.example.com/v1");
      const fromOption = await yunbanPlugin(stub.input, { yunbanBase: "https://option.example.com/" });
      const cfgOption = {};
      await fromOption.config(cfgOption);
      expect(cfgOption.provider[YUNBAN_ID].api).toBe("https://option.example.com/v1");
    } finally {
      delete process.env.YUNBAN_BASE;
    }
  });
});

// ---------------------------------------------------------------- 灵码登录

async function openLingma(mock) {
  const stub = makeStubHost({ providerId: LINGMA_ID });
  const ctrl = new AbortController();
  const login = await lingmaBegin(
    {},
    { input: stub.input, client: stub.input.client, base: mock.base, providerId: LINGMA_ID, signal: ctrl.signal, machineFile: join(scratch, "lingma-machine.json") },
  );
  return { login, stub, ctrl };
}

async function lingmaCallback(mock, { stateParam = "bare", twoOrgs = false } = {}) {
  const ctx = await openLingma(mock);
  if (twoOrgs) mock.state.lingmaOrgs = [{ orgId: "org-a", orgName: "组织A" }, ORG_B];
  const nonce = ctx.login._nonce;
  const blocks = callbackBlocks({ uid: "uid-1", yxUid: "yx-1", name: "回调里的名字", sect: "sect-1", rt: "rt-1", expireTimeMs: 1700000000000 });
  const sp = stateParam === "prefixed" ? `2-${nonce}` : stateParam === "wrong" ? "other" : nonce;
  const html = await fetch(`${ctx.login._page.url}/auth/callback?state=${sp}&auth=${encodeURIComponent(blocks.auth)}&token=${encodeURIComponent(blocks.token)}`).then((r) => r.text());
  return { ...ctx, html, nonce };
}

describe("灵码登录（假上游）", () => {
  let mock;
  beforeEach(() => {
    mock?.stop();
    mock = createMockUpstream();
  });

  test("单组织：回调后自动完成；宿主判定成功；令牌取回调、有效期取 status", async () => {
    const { login, html } = await lingmaCallback(mock);
    expect(html).toContain("登录完成");
    const { ok, stored } = await hostCallback(login);
    expect(ok).toBe(true);
    expect(stored).toMatchObject({
      type: "oauth",
      refresh: "rt-1", // 回调给的（status 响应回的是另一个值，不采纳）
      access: "sect-1",
      expires: 1893456000000, // status 的 expireTime > 0 → 用它（回调是 1700000000000）
      accountId: "uid-1|org-a",
      uid: "uid-1",
      name: "张三", // status 决定姓名（不是回调里的名字）
      userType: "enterprise_standard",
      organizationId: "org-a",
      organizationName: "组织A",
      refreshToken: "rt-1",
      securityOauthToken: "sect-1",
      expireTimeMs: 1893456000000,
    });
    expect(stored.machineId).toMatch(/^[0-9a-f-]{36}$/);
    expect(stored.key.length).toBe(172);
    expect(JSON.stringify(stored)).not.toContain("MUST-NOT-BE-USED");
    // A 族信封：encodeVersion 1 + 双层 payload
    const envelope = mock.state.requests.find((r) => r.path === "/algo/api/v3/user/status");
    expect(envelope.headers.appcode).toBe("cosy");
    expect(envelope.headers["user-agent"]).toBe("Go-http-client/1.1");
    expect(envelope.headers["x-request-id"]).toMatch(/^[0-9a-f-]{36}$/);
  });

  test("status 的 expireTime 缺失（0）时沿用回调的 expireTime", async () => {
    mock.state.lingmaStatusExpire = 0;
    const { login } = await lingmaCallback(mock); // 回调里是 1700000000000
    const { ok, stored } = await hostCallback(login);
    expect(ok).toBe(true);
    expect(stored.expireTimeMs).toBe(1700000000000);
    expect(stored.expires).toBe(1700000000000);
  });

  test("A 族三个接口的内层字段集（URL 的 ?Encode=1 由假上游强制校验）", async () => {
    const { login } = await lingmaCallback(mock);
    await hostCallback(login);
    expect(mock.state.aInner["/algo/api/v3/user/grantAuthInfos"]).toEqual({ userId: "uid-1", token: "sect-1" });
    expect(mock.state.aInner["/algo/api/v3/user/status"]).toEqual({
      orgId: "org-a",
      userId: "uid-1",
      token: "sect-1", // 回调下发的 securityOauthToken
      personalToken: "",
      securityOauthToken: "",
      refreshToken: "",
      needRefresh: false,
      authInfo: {},
    });
    const hooks = await lingmaPlugin(makeStubHost({ providerId: LINGMA_ID }).input, { lingmaBase: mock.base });
    await hooks.auth.refresh(lingmaStored());
    expect(mock.state.aInner["/algo/api/v3/user/refresh_token"]).toEqual({ userId: "uid-1", refreshToken: "rt-1", needRefresh: true });
  });

  test("基址来源：options 优先于环境变量 LINGMA_BASE；末尾斜杠剥掉", async () => {
    const input = makeStubHost({ providerId: LINGMA_ID }).input;
    process.env.LINGMA_BASE = "https://env.example.com/";
    try {
      const fromEnv = await lingmaPlugin(input, {});
      const cfgEnv = {};
      await fromEnv.config(cfgEnv);
      expect(cfgEnv.provider[LINGMA_ID].api).toBe("https://env.example.com/v1");
      const fromOption = await lingmaPlugin(input, { lingmaBase: "https://option.example.com/" });
      const cfgOption = {};
      await fromOption.config(cfgOption);
      expect(cfgOption.provider[LINGMA_ID].api).toBe("https://option.example.com/v1");
    } finally {
      delete process.env.LINGMA_BASE;
    }
  });

  test("多组织：页面出现单选，带本页令牌提交后完成；页面不出现回调 nonce", async () => {
    const { login, html, nonce } = await lingmaCallback(mock, { twoOrgs: true });
    expect(html).toContain("选择组织");
    expect(html).toContain("组织A（org-a）");
    expect(html).toContain("组织B（org-b）");
    // 回调 state 的 nonce 不能出现在页面上（只经 URL fragment 给页面令牌）
    expect(html).not.toContain(nonce);
    // 令牌不对：拒绝，登录仍停在组织选择
    const forged = await fetch(`${login._page.url}/org`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "orgId=org-b&t=wrong" }).then((r) => r.text());
    expect(forged).toContain("页面已失效");
    expect(login._state.stage).toBe("orgs");
    const picked = await fetch(`${login._page.url}/org`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: `orgId=org-b&t=${login._token}` }).then((r) => r.text());
    expect(picked).toContain("登录完成");
    const { ok, stored } = await hostCallback(login);
    expect(ok).toBe(true);
    expect(stored.accountId).toBe("uid-1|org-b");
    expect(stored.organizationId).toBe("org-b");
    expect(stored.organizationName).toBe("组织B"); // status 回显覆盖
  });

  test("重复提交幂等：选组织的表单提交两次（双击 / 刷新重发）都显示完成，只产生一份凭据", async () => {
    const { login } = await lingmaCallback(mock, { twoOrgs: true });
    const post = () =>
      fetch(`${login._page.url}/org`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: `orgId=org-a&t=${login._token}` }).then((r) => r.text());
    expect(await post()).toContain("登录完成");
    // 登录完成之后再提交：不能显示失败（已完成的事实不因重复提交而变）
    expect(await post()).toContain("登录完成");
    expect((await Promise.all([post(), post()])).every((t) => t.includes("登录完成"))).toBe(true);
    const first = await hostCallback(login);
    const second = await hostCallback(login);
    expect(first.ok).toBe(true);
    expect(second.stored).toEqual(first.stored);
    expect(mock.count("/algo/api/v3/user/status")).toBe(1); // 只收尾一次
  });

  test("回调 URL 重复访问：都显示完成，只收尾一次", async () => {
    const { login } = await lingmaCallback(mock);
    const first = await hostCallback(login);
    const again = await fetch(login._page.url + "/auth/callback?state=" + login._nonce).then((r) => r.text());
    expect(again).toContain("登录完成");
    expect((await hostCallback(login)).stored).toEqual(first.stored);
    expect(mock.count("/algo/api/v3/user/status")).toBe(1);
  });

  test("state 校验：带 2- 前缀也能匹配；不匹配的 state 显示失效页，不打断登录", async () => {
    const a = await lingmaCallback(mock, { stateParam: "prefixed" });
    expect(a.html).toContain("登录完成");
    const b = await lingmaCallback(mock, { stateParam: "wrong" });
    expect(b.html).toContain("页面已失效");
    // state 不匹配的回调不会让登录失败
    expect(b.login._state.stage).toBe("waiting");
    // 正确的回调随后仍然可以完成
    const blocks = callbackBlocks({ uid: "uid-1", yxUid: "yx-1", name: "回调里的名字", sect: "sect-1", rt: "rt-1" });
    const html = await fetch(
      `${b.login._page.url}/auth/callback?state=${b.nonce}&auth=${encodeURIComponent(blocks.auth)}&token=${encodeURIComponent(blocks.token)}`,
    ).then((r) => r.text());
    expect(html).toContain("登录完成");
    const { ok } = await hostCallback(b.login);
    expect(ok).toBe(true);
  });

  test("回调 token 块的 expireTime：超长数字（Infinity）当 0，不会写进凭据", () => {
    const wire = encode(Buffer.from(["sect", "rt", "9".repeat(400)].join("\n"), "utf8"));
    expect(parseCallbackToken(wire).expireTimeMs).toBe(0);
  });

  test("machine_id 跨登录稳定（同一台机器）", async () => {
    const a = await lingmaCallback(mock);
    const b = await lingmaCallback(mock);
    const s1 = (await hostCallback(a.login)).stored;
    const s2 = (await hostCallback(b.login)).stored;
    expect(s1.machineId).toMatch(/^[0-9a-f-]{36}$/);
    expect(s2.machineId).toBe(s1.machineId);
    expect(s2.encryptUserInfo).toBe(s1.encryptUserInfo); // 材料由 machineId+uid 决定
    // key 是 RSA-PKCS1v15 密文：随机填充，每次不同（长度恒 172）
    expect(s1.key.length).toBe(172);
    expect(s2.key.length).toBe(172);
  });

  test("登录 URL 形状（nonce 32hex、state=2-nonce、machine_id 带连字符、S256、challenge 86 字符）", async () => {
    const { login } = await openLingma(mock);
    const u = new URL(login.url);
    expect(u.origin).toBe(mock.base);
    expect(u.pathname).toBe("/lingma/login");
    expect(u.searchParams.get("nonce")).toMatch(/^[0-9a-f]{32}$/);
    expect(u.searchParams.get("state")).toBe(`2-${u.searchParams.get("nonce")}`);
    expect(u.searchParams.get("machine_id")).toMatch(/^[0-9a-f-]{36}$/);
    expect(u.searchParams.get("challenge_method")).toBe("S256");
    expect(u.searchParams.get("challenge").length).toBe(86);
    expect(u.searchParams.get("port")).toBe(String(login._page.port));
    expect(login.method).toBe("auto");
    expect(typeof login.callback).toBe("function");
    expect(login.instructions).toContain("SSO");
  });

  test("宿主取消登录（callback 的 signal 中止）→ 以失败收尾并关掉本地页", async () => {
    const { login } = await openLingma(mock);
    const ctrl = new AbortController();
    const pending = hostCallback(login, { signal: ctrl.signal });
    ctrl.abort();
    const { ok, error } = await pending;
    expect(ok).toBe(false);
    expect(error).toBe("登录已取消");
    await expect(fetch(`${login._page.url}/done`).then((r) => r.status)).rejects.toBeTruthy();
  });
});

// ---------------------------------------------------------------- 灵码 chat / hooks

describe("灵码会话与 chat（假上游）", () => {
  let mock;
  beforeEach(() => {
    mock?.stop();
    mock = createMockUpstream();
  });
  const plug = (stub, extra = {}) => lingmaPlugin(stub.input, { lingmaBase: mock.base, firstByteMs: 150, idleMs: 400, ...extra });
  const withHangAndSlow = () => {
    mock.state.lingmaExtraModels = [
      { key: "org_hang_x", display_name: "hang", max_input_tokens: 0 },
      { key: "org_slow_x", display_name: "slow", max_input_tokens: 0 },
    ];
  };

  test("provider.models：四类归一化 + 去重（quest 不取）；公开 id = api.id = key", async () => {
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const hooks = await plug(stub);
    const out = await hooks.provider.models({ models: {} }, { auth: lingmaStored() });
    expect(Object.keys(out)).toEqual(["org_glm-5_x"]);
    expect(out["org_glm-5_x"]).toMatchObject({
      id: "org_glm-5_x",
      name: "m",
      api: { id: "org_glm-5_x", npm: "@ai-sdk/openai-compatible" },
      limit: { context: 200000, output: 0 },
      capabilities: { reasoning: false, toolcall: true, input: { text: true }, output: { text: true } },
    });
  });

  test("chat 端到端：B 族 23 头、agent 请求形状、SSE 渲染（无 include_usage 不发 usage）", async () => {
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const caller = await makeCaller(await plug(stub), { auth: lingmaStored() });
    const resp = await caller.chat({ model: "m", stream: true, messages: MSGS });
    expect(resp.status).toBe(200);
    expect(resp.headers.get("content-type")).toContain("text/event-stream");
    const text = await resp.text();
    expect(shapesOf(text)).toEqual(["role", "content", "finish:stop", "DONE"]);

    const req = mock.state.requests.find((r) => r.path === "/algo/api/v2/service/pro/sse/agent_chat_generation");
    expect(req.headers.authorization.startsWith("Bearer COSY.")).toBe(true);
    expect(req.headers["cosy-sigpath"]).toBe("/api/v2/service/pro/sse/agent_chat_generation");
    expect(req.headers["cosy-user"]).toBe("uid-1");
    expect(req.headers["cosy-organization-id"]).toBe("org-a");
    expect(req.headers["cosy-machineid"]).toBe(lingmaStored().machineId);
    expect(req.headers["cosy-machineos"]).toBe("x86_64_windows");
    expect(req.headers["cosy-clienttype"]).toBe("2");
    expect(req.headers["cosy-clientip"]).toBe("169.254.26.114");
    expect(req.headers["cosy-data-policy"]).toBe("DISAGREE");
    expect(req.headers["cosy-version"]).toBe("3.4.0");
    expect(req.headers["login-version"]).toBe("v2");
    expect(req.headers["cosy-clienttype"]).toBe("2");
    expect(req.headers.accept).toBe("text/event-stream");
    expect(req.headers["x-model-key"]).toBe("org_glm-5_x");
    expect(req.headers["x-model-source"]).toBe("organization");
    expect(req.headers["x-request-id"]).toBe(mock.state.lastLingmaAgent.request_set_id);
    // cosy-date 与签名用的 ts 是同一个，且是秒
    expect(req.headers["cosy-date"]).toMatch(/^\d{10}$/);

    const agent = mock.state.lastLingmaAgent;
    expect(agent.chat_task).toBe("FREE_INPUT");
    expect(agent.chat_context.text).toBe("你好");
    expect(agent.model_config).toMatchObject({ key: "org_glm-5_x", display_name: "m", max_input_tokens: 200000, source: "organization" });
    expect(agent.tools).toBeNull();
    expect(agent.request_set_id).toBe(agent.chat_record_id);
  });

  test("include_usage=true：同帧 usage 取到；工具调用帧透传", async () => {
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const caller = await makeCaller(await plug(stub), { auth: lingmaStored() });
    const resp = await caller.chat({ model: "m", stream: true, messages: MSGS, stream_options: { include_usage: true } });
    const text = await resp.text();
    expect(shapesOf(text)).toEqual(["role", "content", "finish:stop", "usage", "DONE"]);
    expect(text).toContain('"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}');
  });

  test("长流不被掐：建连超时 150ms，流持续近 1 秒仍完整", async () => {
    withHangAndSlow();
    mock.state.lingmaChat.mode = "slow";
    const stub = makeStubHost({ providerId: LINGMA_ID });
    // idle 放宽到 2s，避免较慢的机器上块间超时误报
    const caller = await makeCaller(await plug(stub, { idleMs: 2000 }), { auth: lingmaStored() });
    const text = await (await caller.chat({ model: "org_slow_x", stream: true, messages: MSGS })).text();
    expect(shapesOf(text).filter((s) => s === "content").length).toBe(12);
    expect(shapesOf(text).slice(-2)).toEqual(["finish:stop", "DONE"]);
  });

  test("空闲超时：吐一帧后挂住 → 错误事件 + [DONE]，不补 stop", async () => {
    mock.state.lingmaChat.mode = "hang";
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const caller = await makeCaller(await plug(stub), { auth: lingmaStored() });
    const text = await (await caller.chat({ model: "m", stream: true, messages: MSGS })).text();
    expect(shapesOf(text)).toEqual(["role", "content", "error", "DONE"]);
    expect(text).toContain("上游流超过 400ms 无数据");
    expect(text).not.toContain('"finish_reason":"stop"');
  });

  test("下游取消 → 上游连接立刻断开", async () => {
    mock.state.lingmaChat.mode = "hang";
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const caller = await makeCaller(await plug(stub, { idleMs: 60000 }), { auth: lingmaStored() });
    const resp = await caller.chat({ model: "m", stream: true, messages: MSGS });
    const reader = resp.body.getReader();
    await reader.read();
    const upstream = mock.state.chatSignals.at(-1);
    expect(upstream.aborted).toBe(false);
    await reader.cancel("client gone");
    expect(await until(() => upstream.aborted)).toBe(true);
  });

  test("尾随 system 在发给上游前重排", async () => {
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const caller = await makeCaller(await plug(stub), { auth: lingmaStored() });
    await caller.chat({
      model: "m",
      messages: [
        { role: "system", content: "S1" },
        { role: "user", content: "U" },
        { role: "assistant", content: "A" },
        { role: "system", content: "S2" },
      ],
    });
    expect(mock.state.lastLingmaAgent.messages.map((m) => [m.role, m.content])).toEqual([
      ["system", "S1"],
      ["system", "S2"],
      ["user", "U"],
      ["assistant", "A"],
    ]);
  });

  test("模型严格匹配：key 与 display_name 都能查；未命中 400 并列出可用模型", async () => {
    withHangAndSlow();
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const caller = await makeCaller(await plug(stub), { auth: lingmaStored() });
    expect((await caller.chat({ model: "org_glm-5_x", messages: MSGS })).status).toBe(200);
    const miss = await caller.chat({ model: "gpt-4o", messages: MSGS });
    expect(miss.status).toBe(400);
    expect(miss.headers.get("x-magpie-sign-in")).toBe("kept");
    const msg = (await miss.json()).error.message;
    expect(msg).toContain("gpt-4o");
    expect(msg).toContain("可用模型");
    expect(msg).toContain("hang");
  });

  test("模型目录缓存：5 分钟内多次 chat 只打一次 model/list", async () => {
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const caller = await makeCaller(await plug(stub), { auth: lingmaStored() });
    expect((await caller.chat({ model: "m", messages: MSGS })).status).toBe(200);
    expect((await caller.chat({ model: "org_glm-5_x", messages: MSGS })).status).toBe(200);
    expect(mock.count("/algo/api/v2/model/list")).toBe(1);
  });

  test("模型目录并发合并：冷启动的并发 chat 共享一次 model/list", async () => {
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const hooks = await plug(stub);
    const caller = await makeCaller(hooks, { auth: lingmaStored() });
    const resps = await Promise.all([1, 2, 3].map(() => caller.chat({ model: "m", messages: MSGS })));
    expect(resps.every((r) => r.status === 200)).toBe(true);
    await Promise.all(resps.map((r) => r.text()));
    expect(mock.count("/algo/api/v2/model/list")).toBe(1);
  });

  test("目录缓存过期后刷新失败：沿用上一份，对话不受影响；没有旧目录时才报错", async () => {
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const hooks = await plug(stub, { modelsTtlMs: 1 }); // 每次都视为过期
    const auth = lingmaStored();
    expect((await makeCaller(hooks, { auth }).then((c) => c.chat({ model: "m", messages: MSGS }))).status).toBe(200);
    await Bun.sleep(10); // TTL 是 1ms：跨过同毫秒，避免缓存命中
    mock.state.lingmaModelListStatus = 503;
    const caller = await makeCaller(hooks, { auth });
    expect((await caller.chat({ model: "m", messages: MSGS })).status).toBe(200); // 沿用上一份
    expect(mock.count("/algo/api/v2/model/list")).toBe(2);
    // 没有缓存的账号：目录不可用 → 502 kept；401 → expired（登录失效要如实上报）
    const other = await makeCaller(hooks, { auth: { ...auth, uid: "uid-2", accountId: "uid-2|org-a" } });
    const fail = await other.chat({ model: "m", messages: MSGS });
    expect(fail.status).toBe(502);
    expect(fail.headers.get("x-magpie-sign-in")).toBe("kept");
    mock.state.lingmaModelListStatus = 401;
    const expired = await other.chat({ model: "m", messages: MSGS });
    expect(expired.status).toBe(401);
    // 上游 401 不带 sign-in 头：宿主会先走 staleAccess（access 未到期则续期）
    expect(expired.headers.get("x-magpie-sign-in")).toBeNull();
    // 401 不吃旧目录：有缓存的账号同样如实上报
    expect((await caller.chat({ model: "m", messages: MSGS })).status).toBe(401);
  });

  test("上游状态映射：429→429 kept；400→400；500→502；401→401（不带头，交给宿主续期）", async () => {
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const caller = await makeCaller(await plug(stub), { auth: lingmaStored() });
    for (const [up, want, signIn] of [
      [429, 429, "kept"],
      [400, 400, "kept"],
      [500, 502, "kept"],
      [401, 401, null],
    ]) {
      mock.state.lingmaChat.status = up;
      const resp = await caller.chat({ model: "m", messages: MSGS });
      expect(resp.status).toBe(want);
      expect(resp.headers.get("x-magpie-sign-in")).toBe(signIn);
      expect((await resp.json()).error.message).toContain("上游拒绝");
    }
  });

  test("200 但不是流（JSON 信封）→ 502 kept「上游未返回流式响应」", async () => {
    mock.state.lingmaChat.mode = "json";
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const caller = await makeCaller(await plug(stub), { auth: lingmaStored() });
    const resp = await caller.chat({ model: "m", messages: MSGS });
    expect(resp.status).toBe(502);
    expect(resp.headers.get("x-magpie-sign-in")).toBe("kept");
    expect((await resp.json()).error.message).toContain("上游未返回流式响应");
  });

  test("上游不可达 → 502 kept，文案含私有网络提示", async () => {
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const caller = await makeCaller(await lingmaPlugin(stub.input, { lingmaBase: "http://127.0.0.1:9" }), { auth: lingmaStored() });
    const resp = await caller.chat({ model: "m", messages: MSGS });
    expect(resp.status).toBe(502);
    expect(resp.headers.get("x-magpie-sign-in")).toBe("kept");
    expect((await resp.json()).error.message).toContain("私有网络");
  });

  test("非 chat 请求 → 400；未登录 / 缺签名材料 → 401 expired", async () => {
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const hooks = await plug(stub);
    const caller = await makeCaller(hooks, { auth: lingmaStored() });
    const emb = await caller.embeddings({ input: "x" });
    expect(emb.status).toBe(400);
    expect((await emb.json()).error.message).toBe("只提供 chat completions");
    expect((await makeCaller(hooks, { auth: undefined }).then((c) => c.chat({ model: "m", messages: MSGS }))).status).toBe(401);
    const noMaterial = await makeCaller(hooks, { auth: { ...lingmaStored(), key: "", encryptUserInfo: "" } }).then((c) => c.chat({ model: "m", messages: MSGS }));
    expect(noMaterial.status).toBe(401);
    expect(noMaterial.headers.get("x-magpie-sign-in")).toBe("expired");
  });

  test("畸形 messages（[null]）→ 400，不是可重试的 502", async () => {
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const caller = await makeCaller(await plug(stub), { auth: lingmaStored() });
    const resp = await caller.chat({ model: "m", messages: [null] });
    expect(resp.status).toBe(400);
    expect(resp.headers.get("x-magpie-sign-in")).toBe("kept");
    expect((await resp.json()).error.message).toContain("messages[0]");
  });

  test("refresh：只换令牌 / 有效期 / uid，材料不动；400 → kept（可重试）；401 → expired", async () => {
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const hooks = await plug(stub);
    const auth = lingmaStored();
    const next = await hooks.auth.refresh(auth);
    expect(next).toEqual({
      access: "sect-2",
      refresh: "rt-2",
      expires: 1893456000000,
      uid: "uid-1",
      securityOauthToken: "sect-2",
      refreshToken: "rt-2",
      expireTimeMs: 1893456000000,
    }); // 只回变化的字段（宿主浅合并），key/encryptUserInfo 不在其中
    await expect(hooks.auth.refresh({ ...auth, refreshToken: "dead-rt", refresh: "dead-rt" })).rejects.toMatchObject({ signIn: "kept" });
    await expect(hooks.auth.refresh({ ...auth, refreshToken: "expired-rt", refresh: "expired-rt" })).rejects.toMatchObject({ signIn: "expired" });
    // 200 但缺令牌 → kept，旧会话不被覆盖成空串
    mock.state.lingmaRefreshEmpty = true;
    await expect(hooks.auth.refresh(auth)).rejects.toMatchObject({ signIn: "kept" });
    mock.state.lingmaRefreshEmpty = false;
    // 200 带令牌但缺 id：错误消息不带响应体（宿主会原样写进日志）
    mock.state.lingmaRefreshNoId = true;
    const leak = await hooks.auth.refresh(auth).catch((e) => e);
    mock.state.lingmaRefreshNoId = false;
    expect(leak.signIn).toBe("expired");
    expect(leak.message).not.toContain("SECRET");
    // uid 变了 → kept（不覆盖旧会话）
    await expect(hooks.auth.refresh({ ...auth, uid: "uid-OTHER", accountId: "uid-OTHER|org-a" })).rejects.toMatchObject({ signIn: "kept" });
    // expireTime 缺失时回退旧值（expireTimeMs 没有就看 expires），不能写 0
    mock.state.lingmaRefreshNoExpire = true;
    const noExp = await hooks.auth.refresh({ ...auth, expireTimeMs: 0, expires: 1893456000000 });
    mock.state.lingmaRefreshNoExpire = false;
    expect(noExp.expireTimeMs).toBe(1893456000000);
    const offline = await lingmaPlugin(stub.input, { lingmaBase: "http://127.0.0.1:9" });
    const err = await offline.auth.refresh(auth).catch((e) => e);
    expect(err.signIn).toBe("kept");
    expect(err.message).not.toMatch(/token|session|登录|过期/i);
  });

  test("usage：灵码不提供权益 → kept（不返回不带 signIn 的成功结果）", async () => {
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const hooks = await plug(stub);
    expect(await hooks.auth.usage(async () => lingmaStored())).toEqual({ signIn: "kept" });
  });
});

// ---------------------------------------------------------------- 端到端贯通
// 走插件的 authorize 入口 → 本地页 / 回调 → 宿主判定并保存（hostCallback）→
// 用保存后的凭据走目录 / 对话 / 续期 / 权益。

describe("端到端贯通：登录 → 宿主落盘 → 对话（假上游）", () => {
  let mock;
  beforeEach(() => {
    mock?.stop();
    mock = createMockUpstream();
  });

  test("云伴：authorize → 图形码 → 落盘 → 目录 / 对话 / 续期 / 权益", async () => {
    const stub = makeStubHost({ providerId: YUNBAN_ID });
    const hooks = await yunbanPlugin(stub.input, { yunbanBase: mock.base, deviceFile: join(scratch, "e2e-device.json") });
    // 1) authorize 必须很快返回（宿主给的期限是 1 分钟），只交出页面地址与 callback
    const started = Date.now();
    const login = await hooks.auth.methods[0].authorize({ loginMode: "local", username: "u1", password: PASSWORD }, { signal: new AbortController().signal });
    expect(Date.now() - started).toBeLessThan(5000);
    expect(login.method).toBe("auto");
    // token 只经 URL fragment 交给页面（不进 HTML/Referer/历史）
    expect(login.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/#t=[0-9a-f-]{36}$/);
    expect(typeof login.callback).toBe("function");
    const api = (path, body) =>
      fetch(`${login._page.url}${path}`, {
        method: body === undefined ? "GET" : "POST",
        headers: { "x-login-token": login._token, ...(body === undefined ? {} : { "content-type": "application/json" }) },
        body: body === undefined ? undefined : JSON.stringify(body),
      }).then((r) => r.json());
    // 2) 图形码
    await api("/captcha");
    expect((await api("/submit", { captchaId: "c1", captchaCode: "1234" })).stage).toBe("done");
    // 3) 宿主判定并落盘
    const { ok, stored } = await hostCallback(login);
    expect(ok).toBe(true);
    // 4) 用落盘后的凭据
    const caller = await makeCaller(hooks, { auth: stored });
    expect(Object.keys(await hooks.provider.models({}, { auth: stored }))).toEqual(["m1"]);
    const resp = await caller.chat({ model: "m1", stream: true, messages: MSGS });
    expect(resp.status).toBe(200);
    expect(shapesOf(await resp.text())).toEqual(["role", "content", "finish:stop", "DONE"]);
    const renewed = await hooks.auth.refresh(stored);
    expect(renewed.sessionKey).toBe(stored.sessionKey);
    expect(minutesAway(renewed.expires)).toBeGreaterThan(29);
    expect((await hooks.auth.usage(async () => stored)).plan).toBe("组织");
    expect(JSON.stringify(stored)).not.toContain(PASSWORD);
  });

  test("灵码：authorize → SSO 回调 → 落盘 → 目录 / 对话 / 续期", async () => {
    const stub = makeStubHost({ providerId: LINGMA_ID });
    const hooks = await lingmaPlugin(stub.input, { lingmaBase: mock.base, machineFile: join(scratch, "e2e-machine.json") });
    const started = Date.now();
    // 没问 prompts 的方法，宿主这样调用：authorize(undefined, { signal })
    const login = await hooks.auth.methods[0].authorize(undefined, { signal: new AbortController().signal });
    expect(Date.now() - started).toBeLessThan(5000);
    expect(login.url.startsWith(`${mock.base}/lingma/login?`)).toBe(true);
    // 浏览器回调
    const blocks = callbackBlocks({ uid: "uid-1", yxUid: "yx-1", name: "回调里的名字", sect: "sect-1", rt: "rt-1", expireTimeMs: 1893456000000 });
    const html = await fetch(`${login._page.url}/auth/callback?state=${login._nonce}&auth=${encodeURIComponent(blocks.auth)}&token=${encodeURIComponent(blocks.token)}`).then((r) => r.text());
    expect(html).toContain("登录完成");
    const { ok, stored } = await hostCallback(login);
    expect(ok).toBe(true);
    const caller = await makeCaller(hooks, { auth: stored });
    expect(Object.keys(await hooks.provider.models({}, { auth: stored }))).toEqual(["org_glm-5_x"]);
    const resp = await caller.chat({ model: "m", stream: true, messages: MSGS, stream_options: { include_usage: true } });
    expect(shapesOf(await resp.text())).toEqual(["role", "content", "finish:stop", "usage", "DONE"]);
    // 上游看到的 B 族头确实来自落盘凭据（uid / 组织 / 机器码 / 合成材料）
    const req = mock.state.requests.find((r) => r.path === "/algo/api/v2/service/pro/sse/agent_chat_generation");
    expect(req.headers["cosy-user"]).toBe("uid-1");
    expect(req.headers["cosy-organization-id"]).toBe(stored.organizationId);
    expect(req.headers["cosy-machineid"]).toBe(stored.machineId);
    expect(req.headers["cosy-key"]).toBe(stored.key);
    expect(JSON.parse(Buffer.from(req.headers.authorization.split(".")[1], "base64").toString()).info).toBe(stored.encryptUserInfo);
    const renewed = await hooks.auth.refresh(stored);
    expect(renewed.access).toBe("sect-2");
    expect(renewed.key).toBeUndefined(); // 只回变化的字段：宿主浅合并后材料仍是落盘的那份
  });
});

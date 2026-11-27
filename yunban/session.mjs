// 云伴账号的凭据形状、/me 合并规则、权益判定。
// 不保存密码：会话失效后需要重新登录。

// auth 记录里属于本 provider 的字段（不含 type：登录结果交给宿主时是
// type:"success"，落盘由宿主改写成 type:"oauth"）：
// { refresh:<sessionKey>, access:<token>, expires:<毫秒>,
//   accountId, token, sessionKey, expiresAt(RFC3339), deviceId,
//   loginMode("local"|"sso"), username, identity:{issuer,tenantId,subject}, user:{userId,name} }

// 续期：上游没有 refresh 接口，客户端定期调用 /me 换取滑动令牌。
// expires 固定填「现在 + 30 分钟」，宿主在到期前调用 auth.refresh（即 /me），
// 每次续期把它再推后 30 分钟。长时间不调用 /me，会话会失效。
export const RENEW_EVERY_MS = 30 * 60 * 1000;
export const nextExpiry = (now = Date.now()) => now + RENEW_EVERY_MS;

// 把 /me 响应合并进 auth 记录：
// - identity 的 issuer / tenantId / subject：是字符串才覆盖
// - token / expiresAt：非空才覆盖
// - user.userId：非 0 才覆盖；user.name：非空才覆盖
// - sessionKey 不变（/me 响应里没有它）
// expires / refresh 不动：expires 由续期逻辑给（见上）。
export function mergeMe(auth, me) {
  const next = { ...auth, identity: { ...(auth.identity ?? {}) }, user: { ...(auth.user ?? {}) } };
  const id = me?.identity;
  if (id && typeof id === "object") {
    for (const k of ["issuer", "tenantId", "subject"]) {
      if (typeof id[k] === "string") next.identity[k] = id[k];
    }
  }
  if (typeof me?.token === "string" && me.token) {
    next.token = me.token;
    next.access = me.token;
  }
  if (typeof me?.expiresAt === "string" && me.expiresAt) {
    next.expiresAt = me.expiresAt;
  }
  const user = me?.user;
  if (user && typeof user === "object") {
    const uid = user.userId;
    if (typeof uid === "number" && uid !== 0) next.user.userId = uid;
    if (typeof user.name === "string" && user.name) next.user.name = user.name;
  }
  return next;
}

// 账号标识：/me 的 user.userId，缺失回退 user.name，再缺失用 username。
export function accountIdOf(auth) {
  const uid = auth?.user?.userId;
  if (typeof uid === "number" && uid !== 0) return String(uid);
  if (auth?.user?.name) return auth.user.name;
  return auth?.username ?? "";
}

// ---------------- 权益（/me/account） ----------------

// 提取三个顶层对象（org/seat/credits）；顶层多余字段丢弃。
export function parseEntitlement(v) {
  const pick = (o) => (o && typeof o === "object" && !Array.isArray(o) ? o : undefined);
  return { org: pick(v?.org), seat: pick(v?.seat), credits: pick(v?.credits) };
}

// 权益是否允许发起请求（只列出不可用的情况）：
// 1. seat.suspended === true，或 seat.status 为 not_issued / expired / suspended → 不可用
// 2. credits.remaining <= 0 且 overageMode 不是 "bill" → 不可用
// 其余情况可用（含 expiring 与未知状态）；字段缺失或解析失败时可用。
export function entitlementUsable(ent) {
  if (ent?.seat) {
    if (ent.seat.suspended === true) return false;
    const status = ent.seat.status;
    if (status === "not_issued" || status === "expired" || status === "suspended") return false;
  }
  if (ent?.credits) {
    const remaining = ent.credits.remaining;
    if (typeof remaining === "number" && remaining <= 0) {
      if (ent.credits.overageMode !== "bill") return false;
    }
  }
  return true;
}

// 席位为什么不可用（给 usage 的 error 文案）；可用时返回空串。
export function seatProblem(seat) {
  if (!seat) return "";
  if (seat.suspended === true) return "席位已暂停";
  const status = seat.status;
  if (status === "not_issued") return "席位未开通";
  if (status === "expired") return "席位已过期";
  if (status === "suspended") return "席位已暂停";
  return "";
}

// /me/account → 宿主的 usage 形状：
// - 当期积分 → {name:"积分", used:<已用百分比，下界 0、不封顶>, amount:<consumed>,
//   limit:<funded>, unit:"credits"}，不带 aside（aside 表示旁注，不参与额度判断）。
//   used 是百分比，amount / limit 才是计数；把 consumed 填进 used 会让
//   100/1000 显示成已用尽。
// - 席位 → {name:"席位", display, aside:true}
// - plan → org.name，没有则不带
// 不设 credits: true：它表示「窗口用尽后靠持有积分继续」，不是「这是积分窗口」。
export function usageFromEntitlement(ent) {
  const out = {};
  if (ent?.org?.name) out.plan = ent.org.name;
  const windows = [];
  const seat = ent?.seat;
  if (seat) {
    // /me/account 不给席位人数：org 带人数字段时显示「已用 / 总数」，否则显示有效期或状态
    const org = ent.org ?? {};
    const used = org.seatUsed ?? org.usedSeats ?? org.memberCount;
    const total = org.seatTotal ?? org.totalSeats;
    let display;
    if (typeof used === "number" && typeof total === "number") display = `${used} / ${total}`;
    else if (seat.validTo) display = `有效期至 ${seat.validTo}`;
    else display = String(seat.status ?? "");
    windows.push({ name: "席位", display, aside: true });
  }
  const credits = ent?.credits;
  if (credits && typeof credits.funded === "number") {
    const consumed = typeof credits.consumed === "number" ? credits.consumed : 0;
    const round = (n) => Math.round(n * 100) / 100;
    const window = { name: "积分", amount: round(consumed), limit: round(credits.funded), unit: "credits" };
    // 只钳下界：宿主支持 used > 100 表示超额（overageMode=bill 时 consumed 可超 funded）
    if (credits.funded > 0) window.used = round(Math.max(0, (consumed / credits.funded) * 100));
    windows.push(window);
  }
  if (windows.length) out.windows = windows;
  return out;
}

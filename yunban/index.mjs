// 云伴 provider 的 Magpie 插件 hooks：config / provider.models / auth。
// provider id：omni2api-yunban（发布后不可改）。
import { beginLogin } from "./login.mjs";
import { postSignedRaw, signedJson, parseUpstreamError, classifiedError } from "./upstream.mjs";
import {
  mergeMe,
  parseEntitlement,
  entitlementUsable,
  usageFromEntitlement,
  seatProblem,
  nextExpiry,
} from "./session.mjs";
import {
  errorResponse,
  log,
  isNetworkError,
  networkErrorMessage,
  guardStream,
  intOption,
  bodyTextOf,
  readErrorText,
  redact,
} from "../common/http.mjs";

export const YUNBAN_ID = "omni2api-yunban";
const NO_BASE = "未配置 yunbanBase：请在 Magpie 的插件设置里填写上游服务地址";

export async function yunbanPlugin(input, options) {
  const ID = YUNBAN_ID;
  // 上游基址必须由使用者配置（不在代码里内置任何部署地址）：
  // 插件设置（options）优先，其次环境变量 YUNBAN_BASE
  const base = String(options?.yunbanBase ?? process.env.YUNBAN_BASE ?? "").trim().replace(/\/+$/, "");
  const client = input?.client;
  const warn = (level, message, secrets) => log(client, level, message, secrets);
  // 流的超时，可由 options 覆盖：只有建连 / 首块与空闲，没有总超时
  const firstByteMs = intOption(options?.firstByteMs, 60000);
  const idleMs = intOption(options?.idleMs, 180000);

  // 只接受 chat completions。embeddings / rerank / audio / images / videos 请求也会
  // 到达同一个 fetch，这里显式拒绝。
  async function dispatch({ getAuth, init, bodyText }) {
    if (!base) return errorResponse(502, NO_BASE, "kept");
    let req = null;
    try {
      req = JSON.parse(bodyText);
    } catch {
      req = null;
    }
    if (!req || !Array.isArray(req.messages)) {
      return errorResponse(400, "只提供 chat completions", "kept");
    }
    // 每请求重读凭据（loader 每账号只跑一次并缓存）
    const auth = await getAuth();
    if (!auth?.access || !auth?.sessionKey) {
      return errorResponse(401, "云伴账号未登录或会话不完整，请重新登录", "expired");
    }
    return chatPassThrough({ auth, init, bodyText });
  }

  // chat：POST /v1/chat/completions，按字节透传：签名后转发，原样返回上游的
  // content-type 和 body 流。请求体里的 model 已是上游模型 id，不需要映射。
  async function chatPassThrough({ auth, init, bodyText }) {
    const path = "/v1/chat/completions";
    let resp;
    try {
      resp = await postSignedRaw(base, auth.access, auth.sessionKey, path, bodyText, { signal: init.signal, firstByteMs });
    } catch (e) {
      if (init.signal?.aborted && e?.name === "AbortError") throw e; // 调用方取消：原样抛出
      if (isNetworkError(e, init.signal)) return errorResponse(502, networkErrorMessage(base, e), "kept");
      throw e;
    }
    if (!resp.ok) {
      const text = await readErrorText(resp);
      const [code, message] = parseUpstreamError(resp.status, text);
      const e = classifiedError(resp.status, code, message);
      // 状态映射在 classifiedError 里：401 → 401 + expired；429 → 429；其它 4xx → 400；
      // 5xx 与跳转 → 502。文案用上游原文。
      const guide = e.signIn === "expired" ? "；请重新登录云伴账号" : "";
      return errorResponse(e.httpStatus ?? 502, `[${code}] ${message}${guide}`, e.signIn);
    }
    if (!resp.body) return errorResponse(502, "上游未返回流式响应", "kept");
    const headers = new Headers();
    headers.set("content-type", resp.headers.get("content-type") ?? "application/json");
    // 成功响应不带 X-Magpie-Sign-In：宿主对 kept 不做处理，不带该头的 2xx 才会
    // 清除账号的失效标记。带 kept 会让曾标记失效、后来恢复的账号一直不恢复。
    // 空闲检测：首块 firstByteMs、块间 idleMs，不设总超时；下游取消时断开上游。
    const body = guardStream(resp.body, { firstMs: firstByteMs, idleMs });
    return new Response(body, { status: resp.status, headers });
  }

  async function handleFetch({ getAuth, init }) {
    try {
      return await dispatch({ getAuth, init, bodyText: bodyTextOf(init) });
    } catch (e) {
      // 调用方取消时原样抛出；其余错误回 502 + kept
      if (init?.signal?.aborted && e?.name === "AbortError") throw e;
      warn("warn", `云伴请求失败: ${e?.message ?? e}`);
      return errorResponse(502, e?.message ?? "上游请求失败", "kept");
    }
  }

  return {
    config: async (config) => {
      config.provider ??= {};
      // 只设置本 provider 的条目，不覆盖其它插件写入的条目
      const was = config.provider[ID] ?? {};
      config.provider[ID] = {
        name: "云伴",
        npm: "@ai-sdk/openai-compatible",
        api: base + "/v1", // 占位；真正的 baseURL 由 loader 给
        ...was,
        models: { ...(was.models ?? {}) },
      };
    },

    provider: {
      id: ID,
      async models(provider, { auth, signal }) {
        if (!base || auth?.type !== "oauth" || !auth.access || !auth.sessionKey) return provider.models;
        try {
          // 宿主给模型列表的时间预算是 20 秒：留出余量，并透传宿主的 signal
          const v = await signedJson(base, auth.access, auth.sessionKey, "/me/models", { timeoutMs: 18000, signal });
          const list = Array.isArray(v?.models) ? v.models : [];
          if (!list.length) return provider.models;
          // 与宿主给的列表合并：config 里补充或覆盖的模型不会被这里的返回值冲掉
          return {
            ...Object.fromEntries(
              list
                .filter((m) => typeof m?.id === "string" && m.id)
                .map((m) => [
                  m.id,
                  {
                    id: m.id,
                    name: typeof m.label === "string" && m.label ? m.label : m.id,
                    // api.id 承载上游标识；云伴公开 id 与上游 id 相同
                    api: { id: m.id, npm: "@ai-sdk/openai-compatible" },
                    limit: {
                      context: typeof m.contextTokens === "number" ? m.contextTokens : 0,
                      output: typeof m.maxOutputTokens === "number" ? m.maxOutputTokens : 0,
                    },
                    capabilities: {
                      reasoning: m.thinking === true,
                      toolcall: true,
                      input: { text: true },
                      output: { text: true },
                    },
                  },
                ]),
            ),
            ...provider.models,
          };
        } catch (e) {
          if (e?.signIn === "expired") throw e; // 让宿主标记账号
          warn("warn", `云伴模型列表读取失败，保留旧列表: ${e?.message ?? e}`);
          return provider.models; // 其余失败保留旧列表
        }
      },
    },

    auth: {
      provider: ID,
      refreshLead: 5 * 60 * 1000,
      // 上游没有 refresh 接口：续期就是调用 /me 换取滑动令牌（sessionKey 不变），
      // 每次把 expires 推后 30 分钟，宿主大约每 25 分钟调用一次。
      refresh: async (auth) => {
        if (!base || auth?.type !== "oauth" || !auth.access || !auth.sessionKey) return undefined;
        try {
          const me = await signedJson(base, auth.access, auth.sessionKey, "/me", { timeoutMs: 20000 });
          return mergeMe({ ...auth, expires: nextExpiry() }, me);
        } catch (e) {
          if (e?.signIn === "expired") {
            // 不保存密码：会话失效后只能重新登录
            throw Object.assign(new Error("云伴会话已失效，请重新登录"), { signIn: "expired" });
          }
          // 网络 / 上游故障时会话仍有效：带 kept，宿主退避重试、不标记账号
          // （续期结果只按 signIn 判定）。错误会原样进入宿主日志：先 redact；
          // 文案不用 token / session / 登录 / 过期这类词，因为会话并没有失效。
          throw Object.assign(new Error(`云伴续期未成功，稍后重试（${redact(e?.message ?? e)}）`), { signIn: "kept" });
        }
      },
      loader: async (getAuth) => ({
        baseURL: base + "/v1",
        apiKey: ID, // 引擎占位；请求真正的凭据在签名头里
        async fetch(_url, init = {}) {
          return handleFetch({ getAuth, init });
        },
      }),
      // 权益：POST /me/account（无请求体）→ 积分窗口 + 席位（旁注）
      usage: async (getAuth, _providerInfo, opts = {}) => {
        if (!base) return { signIn: "kept", error: NO_BASE };
        const auth = await getAuth();
        if (auth?.type !== "oauth" || !auth.access || !auth.sessionKey) return {};
        try {
          const v = await signedJson(base, auth.access, auth.sessionKey, "/me/account", { timeoutMs: 20000, signal: opts.signal });
          const ent = parseEntitlement(v);
          // 读取成功且会话可用时不带 signIn：宿主据此清除账号的失效标记（带 kept 不做处理）。
          const out = usageFromEntitlement(ent);
          if (!entitlementUsable(ent)) {
            // 席位停用或额度用尽：数值照常返回，用 error 说明该账号无法发起请求；
            // 这不是会话失效，带 kept 表示不影响登录状态。
            out.error = `${seatProblem(ent.seat) || "当期额度已用尽"}，该账号无法发起请求`;
            out.signIn = "kept";
          }
          return out;
        } catch (e) {
          if (e?.signIn === "expired") return { error: "需要重新登录", signIn: "expired" };
          return { error: redact(e?.message ?? "权益读取失败"), signIn: "kept" };
        }
      },
      methods: [
        {
          type: "oauth",
          label: "云伴账号（账密 + 验证码）",
          // 宿主支持的 prompt 类型：text / select / password（输入不回显）
          prompts: [
            {
              type: "select",
              key: "loginMode",
              message: "登录方式",
              options: [
                { label: "账号密码", value: "local", hint: "直接用云伴账号密码登录" },
                { label: "企业 SSO（统一认证）", value: "sso", hint: "可能需要短信验证码" },
              ],
            },
            { type: "text", key: "username", message: "账号", placeholder: "账号", validate: nonEmpty("请填写账号") },
            { type: "password", key: "password", message: "密码", placeholder: "只在本次登录使用，不会保存" },
          ],
          // 登录方式 / 账号 / 密码没问到时，本地页上会再让用户填（不会回显已有的）
          authorize: (inputs, opts) => {
            if (!base) throw new Error(NO_BASE);
            return beginLogin(inputs ?? {}, { input, client, base, providerId: ID, signal: opts?.signal, deviceFile: options?.deviceFile });
          },
        },
      ],
    },
  };
}

function nonEmpty(message) {
  return (value) => (String(value ?? "").trim() ? null : message);
}

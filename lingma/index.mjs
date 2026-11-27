// 灵码 provider 的 Magpie 插件 hooks：config / provider.models / auth。
// provider id：omni2api-lingma（发布后不可改）。
import { beginLogin } from "./login.mjs";
import { modelList, refreshSession, chatStream } from "./upstream.mjs";
import { parseChatRequest, resolveModel, buildAgentRequest, includeUsage } from "./oai.mjs";
import { hasMaterial } from "./session.mjs";
import { errorResponse, log, randomUUID, intOption, bodyTextOf, redact } from "../common/http.mjs";
import { sseResponse } from "../common/sse.mjs";

export const LINGMA_ID = "omni2api-lingma";

// 模型目录缓存：每账号 5 分钟。
const MODELS_TTL_MS = 5 * 60 * 1000;
const NO_BASE = "未配置 lingmaBase：请在 Magpie 的插件设置里填写上游服务地址";

export async function lingmaPlugin(input, options) {
  const ID = LINGMA_ID;
  // 上游基址必须由使用者配置（不在代码里内置任何部署地址）：
  // 插件设置（options）优先，其次环境变量 LINGMA_BASE
  const base = String(options?.lingmaBase ?? process.env.LINGMA_BASE ?? "").trim().replace(/\/+$/, "");
  const client = input?.client;
  const warn = (level, message, secrets) => log(client, level, message, secrets);
  // 流的超时，可由 options 覆盖：只有建连 / 首字节与空闲，没有总超时
  const firstByteMs = intOption(options?.firstByteMs, 30000);
  const idleMs = intOption(options?.idleMs, 180000);
  // 模型目录缓存时长（可覆盖；默认 5 分钟）
  const modelsTtlMs = intOption(options?.modelsTtlMs, MODELS_TTL_MS);

  // chat 要做模型严格匹配，需要模型目录；目录按账号缓存，不每个请求都调用 model/list。
  // 刷新失败时沿用上一份（401 除外）。
  // 目录过期后的并发请求共享同一个进行中的请求（pending）；共享请求不挂任何
  // 调用方的 signal（一个调用方取消不影响其它等待者），超时由请求自己的 timeoutMs 控制。
  // 目录接口不可达时退避 30s，避免每个 chat 请求都先等一次超时。
  const modelCache = new Map(); // accountId → { at, models, pending, failedAt, error }
  const RETRY_MS = 30 * 1000;
  const cacheKeyOf = (auth) => String(auth?.accountId || auth?.uid || "");
  const rememberModels = (auth, list) => {
    const key = cacheKeyOf(auth);
    if (!key || !list.length) return;
    const cur = modelCache.get(key);
    // 保留在途请求的 pending，由它收尾时按自己的清理逻辑处理
    modelCache.set(key, { at: Date.now(), models: list, pending: cur?.pending });
  };

  async function modelsFor(auth) {
    const key = cacheKeyOf(auth);
    // 键为空（手工构造的 auth）不缓存，避免多账号共用一份目录
    if (!key) return modelList(base, auth, { timeoutMs: 20000 });
    const hit = modelCache.get(key);
    if (hit?.models?.length && Date.now() - hit.at < modelsTtlMs) return hit.models;
    // 退避窗口：有旧目录先用；没有就把上次的错误原样抛出（不再打上游）
    if (hit?.failedAt && Date.now() - hit.failedAt < RETRY_MS) {
      if (hit.models?.length) return hit.models;
      throw hit.error ?? new Error("灵码模型目录暂不可用");
    }
    const startedAt = hit?.at ?? 0;
    let pending = hit?.pending;
    if (!pending) {
      let self = null;
      self = (async () => {
        try {
          const list = await modelList(base, auth, { timeoutMs: 20000 });
          // 期间 models 钩子可能已写入更新的目录：以较新的那份为准，只清掉 pending
          const cur = modelCache.get(key);
          if (cur?.pending === self) {
            if (list.length && (cur.at ?? 0) <= startedAt) modelCache.set(key, { at: Date.now(), models: list });
            else modelCache.set(key, { at: cur?.at ?? 0, models: cur?.models });
          }
          return list;
        } catch (e) {
          const cur = modelCache.get(key);
          // 失败时清掉 pending、保留旧目录。只在目录接口不可达（网络 / 超时，没有
          // HTTP status）时退避；HTTP 错误（401 / 403 / 5xx）下一次直接重试，
          // 登录失效要如实上报。
          if (cur?.pending === self) {
            const entry = { at: cur?.at ?? 0, models: cur?.models };
            if (!e?.status && e?.signIn !== "expired") {
              entry.failedAt = Date.now();
              entry.error = e;
            }
            modelCache.set(key, entry);
          }
          throw e;
        }
      })();
      modelCache.set(key, { at: hit?.at ?? 0, models: hit?.models, pending: self });
      pending = self;
    }
    try {
      const list = await pending;
      // 200 空列表按刷新失败处理：有旧目录就沿用
      if (!list.length && hit?.models?.length) {
        warn("warn", "灵码模型目录为空，沿用上一份");
        return hit.models;
      }
      return list;
    } catch (e) {
      if (e?.signIn === "expired") throw e;
      if (hit?.models?.length) {
        warn("warn", `灵码模型目录刷新失败，沿用上一份: ${e?.message ?? e}`);
        return hit.models;
      }
      throw e;
    }
  }

  // 上游错误 → 回给宿主的 Response，带显式的 X-Magpie-Sign-In。
  // 上游 401 不带该头：宿主对「access / refresh 与请求开始时相同、未到期」的 401
  // 会先把 expires 置 1，让下一次请求走 auth.refresh；access 被上游提前作废时可以恢复。
  // 其余：429 原样；其它 4xx → 400；5xx / 网络 / 格式错误 → 502。
  // 正文脱敏后可能只剩空白：去掉末尾的冒号，与没有正文时的写法一致。
  const tidy = (m) => String(m ?? "").trim().replace(/[：:]\s*$/, "");
  function errorOf(e) {
    if (e?.httpStatus === 401) return errorResponse(401, tidy(e.message), undefined);
    if (e?.signIn === "expired") return errorResponse(401, `${tidy(e.message)}；请重新登录灵码账号`, "expired");
    return errorResponse(e?.httpStatus ?? 502, tidy(e?.message) || "上游请求失败", "kept");
  }

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
    if (!auth?.access || !hasMaterial(auth)) {
      return errorResponse(401, "灵码账号未登录或签名材料缺失，请重新登录", "expired");
    }
    let parsed;
    try {
      parsed = parseChatRequest(req); // 复用上面已解析的对象，不再 JSON.parse 一遍
    } catch (e) {
      return errorOf(e);
    }
    // 模型严格匹配：完全等于某上游模型的 key 或 display_name（大小写敏感）。
    // 宿主模型缓存未命中时退回公开 id（= key），两种 id 都能查。
    let models;
    try {
      models = await modelsFor(auth);
    } catch (e) {
      return errorOf(e);
    }
    if (!models.length) {
      return errorResponse(502, "上游模型列表为空，请稍后再试", "kept");
    }
    let model;
    try {
      model = resolveModel(parsed.model, models);
    } catch (e) {
      return errorOf(e);
    }
    const setId = randomUUID();
    const agentBody = buildAgentRequest(parsed, model, setId);
    // 上游 fetch 挂在这个 controller 上：下游取消时立即断开。只靠事件源的 return()
    // 要等挂起的读取返回（下一个数据块或空闲超时）才会执行
    const up = new AbortController();
    const outer = init.signal;
    if (outer?.aborted) up.abort(outer.reason);
    else outer?.addEventListener("abort", () => up.abort(outer.reason), { once: true });
    let events;
    try {
      events = await chatStream(base, auth, agentBody, setId, { signal: up.signal, firstByteMs, idleMs });
    } catch (e) {
      if (outer?.aborted && e?.name === "AbortError") throw e;
      return errorOf(e);
    }
    // 只写流式路径：宿主自己从 SSE 聚合非流式
    return sseResponse(events, {
      model: parsed.model,
      includeUsage: includeUsage(parsed),
      signal: outer,
      cancelUpstream: () => up.abort(),
    });
  }

  async function handleFetch({ getAuth, init }) {
    try {
      return await dispatch({ getAuth, init, bodyText: bodyTextOf(init) });
    } catch (e) {
      // 调用方取消时原样抛出；其余错误回 502 + kept
      if (init?.signal?.aborted && e?.name === "AbortError") throw e;
      warn("warn", `灵码请求失败: ${e?.message ?? e}`);
      return errorOf(e);
    }
  }

  return {
    config: async (config) => {
      config.provider ??= {};
      // 只设置本 provider 的条目，不覆盖其它插件写入的条目
      const was = config.provider[ID] ?? {};
      config.provider[ID] = {
        name: "灵码",
        npm: "@ai-sdk/openai-compatible",
        api: base + "/v1", // 占位；真正的 baseURL 由 loader 给
        ...was,
        models: { ...(was.models ?? {}) },
      };
    },

    provider: {
      id: ID,
      async models(provider, { auth, signal }) {
        if (!base || auth?.type !== "oauth" || !auth.access || !hasMaterial(auth)) return provider.models;
        try {
          // 宿主请求目录时返回最新数据（不用缓存），并写入 chat 用的缓存。
          // 宿主给模型列表的时间预算是 20 秒：超时留出余量，并透传宿主的 signal，
          // 调用方不再等待时不再请求上游。
          const list = await modelList(base, auth, { signal, timeoutMs: 18000 });
          if (!list.length) return provider.models;
          rememberModels(auth, list);
          // 与宿主给的列表合并：config 里补充或覆盖的模型不会被这里的返回值冲掉
          return {
            ...Object.fromEntries(
              list.map((m) => [
                m.key, // 公开 id 用上游 key；api.id 同值即不改写
                {
                  id: m.key,
                  name: m.displayName,
                  api: { id: m.key, npm: "@ai-sdk/openai-compatible" },
                  limit: { context: m.maxInputTokens || 0, output: 0 },
                  capabilities: { reasoning: false, toolcall: true, input: { text: true }, output: { text: true } },
                },
              ]),
            ),
            ...provider.models,
          };
        } catch (e) {
          if (e?.signIn === "expired") throw e; // 让宿主标记账号
          warn("warn", `灵码模型列表读取失败，保留旧列表: ${e?.message ?? e}`);
          return provider.models; // 其余失败保留旧列表
        }
      },
    },

    auth: {
      provider: ID,
      refreshLead: 5 * 60 * 1000,
      refresh: async (auth) => {
        const refreshToken = auth?.refreshToken || auth?.refresh;
        if (auth?.type !== "oauth" || !refreshToken) return undefined;
        try {
          // 续期（A 族）只更新令牌与有效期；B 族签名材料由 machineId + uid 派生，不变。
          // 宿主在请求路径上等续期最多 15 秒，超时后用旧令牌继续，续期在后台完成后保存。
          const login = await refreshSession(base, refreshToken, auth.uid, { timeoutMs: 25000 });
          // 令牌为空时宿主浅合并会把 access / refresh 覆盖成空串：响应缺令牌或换了
          // 用户时不返回新值，按可重试处理。
          const oldUid = auth.uid || String(auth.accountId ?? "").split("|")[0];
          if (!login.securityOauthToken || !login.refreshToken || (oldUid && login.uid !== oldUid)) {
            throw Object.assign(new Error("灵码续期响应不完整"), { signIn: "kept" });
          }
          // expireTime 缺失时保留旧值（先看 expireTimeMs，再看 expires），不要写 0
          const oldExpire =
            Number(auth.expireTimeMs) > 0 ? Number(auth.expireTimeMs) : Number(auth.expires) > 0 ? Number(auth.expires) : 0;
          const expire = login.expireTimeMs > 0 ? login.expireTimeMs : oldExpire;
          return {
            access: login.securityOauthToken,
            refresh: login.refreshToken,
            expires: expire,
            uid: login.uid,
            securityOauthToken: login.securityOauthToken,
            refreshToken: login.refreshToken,
            expireTimeMs: expire,
          };
        } catch (e) {
          if (e?.signIn === "expired") {
            // 上游把续期拒了：登录确实失效
            throw Object.assign(new Error("灵码登录已失效，请重新浏览器登录"), { signIn: "expired" });
          }
          // 网络 / 上游故障时会话仍有效：带 kept，宿主退避重试、不标记账号
          // （续期结果只按 signIn 判定）。错误会原样进入宿主日志：先 redact；
          // 文案不用 token / session / 登录 / 过期这类词，因为会话并没有失效。
          throw Object.assign(new Error(`灵码会话续期未成功，稍后重试（${redact(e?.message ?? e)}）`), { signIn: "kept" });
        }
      },
      loader: async (getAuth) => ({
        baseURL: base + "/v1",
        apiKey: ID, // 引擎占位；请求凭据在 B 族签名头里
        async fetch(_url, init = {}) {
          return handleFetch({ getAuth, init });
        },
      }),
      // 灵码不提供权益。返回 kept：不带 signIn 的成功读取会让宿主清除账号的
      // 失效标记，而这里没有做任何上游校验，不能清除该标记。
      usage: async () => ({ signIn: "kept" }),
      methods: [
        {
          type: "oauth",
          label: "灵码账号（浏览器登录）",
          authorize: (inputs, opts) => {
            if (!base) throw new Error(NO_BASE);
            return beginLogin(inputs ?? {}, { input, client, base, providerId: ID, signal: opts?.signal, machineFile: options?.machineFile });
          },
        },
      ],
    },
  };
}

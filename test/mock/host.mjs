// 宿主桩：构造插件函数需要的 input、内存凭据表、loader.fetch 调用器。
// 只实现插件用到的宿主接口：client.app.log、client.auth.set、magpie.account。
export function makeStubHost({ providerId, accountKey }) {
  const key = accountKey ?? providerId;
  const logs = [];
  const authStore = new Map(); // key → auth 记录
  let currentKey = key;
  const input = {
    client: {
      app: {
        log: async (opts) => {
          logs.push({ level: opts?.level ?? "info", message: opts?.message ?? "", service: opts?.service ?? "plugin" });
          return { data: true };
        },
      },
      auth: {
        set: async ({ path, body }) => {
          authStore.set(path?.id ?? key, body);
          return { data: true };
        },
      },
    },
    project: { id: "magpie" },
    magpie: {
      account: (pid) => (pid === providerId ? currentKey : pid),
    },
  };
  return {
    input,
    logs,
    authStore,
    setCurrentKey(k) {
      currentKey = k;
    },
  };
}

// 按宿主的规则：callback() 的返回值 type 不是 "success" 即失败；成功时判断
// 有没有可保存的内容，再拆成 type:"oauth" 的 auth 记录。测试据此判断登录结果
// 是否会被保存。
// 与宿主的一处差别：signal 中止后宿主直接以 AbortError 结束并丢弃插件的返回值，
// 这里仍返回插件给出的结果，供取消测试断言。
// 宿主的调用形式是 callback(undefined, { signal })：opts 原样透传。
export async function hostCallback(login, opts = {}) {
  const r = await login.callback(undefined, opts);
  if (!r || r.type !== "success") {
    return { ok: false, error: typeof r?.error === "string" ? r.error : "" };
  }
  if (!("refresh" in r) && !("key" in r)) {
    if (typeof r.access === "string" && r.access) r.refresh = "";
    else return { ok: false, error: "gave nothing to keep" };
  }
  const { type: _t, provider: _p, refresh, access, expires, ...extra } = r;
  return { ok: true, stored: { type: "oauth", refresh, access, expires, ...extra } };
}

// 从 hooks 构造账号 fetch 调用器：走 auth.loader（与宿主一致），每个请求重新读取凭据。
export async function makeCaller(hooks, { auth, mutate } = {}) {
  let current = auth;
  const getAuth = async () => (mutate ? mutate() : current);
  const load = await hooks.auth.loader(getAuth);
  const call = (path, bodyObj, init = {}) =>
    load.fetch(`https://upstream.invalid${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(bodyObj),
      ...init,
    });
  return {
    load,
    getAuth,
    setAuth(next) {
      current = next;
    },
    chat(bodyObj, init = {}) {
      return call("/v1/chat/completions", bodyObj, init);
    },
    embeddings(bodyObj) {
      return call("/v1/embeddings", bodyObj);
    },
  };
}

// 轮询等条件成立（最多 timeoutMs），用于观测「客户端断开是否传到了上游」。
export async function until(cond, { timeoutMs = 3000, stepMs = 25 } = {}) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    if (cond()) return true;
    if (Date.now() > end) return false;
    await Bun.sleep(stepMs);
  }
}

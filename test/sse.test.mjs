// SSE 渲染时序：首块 role、usage 延后、补 stop、[DONE] 必发（出错后也发）。
// 以及流读写层（common/http.mjs）：空闲超时、背压不误报、取消向上游传播、网络错误识别。
import { describe, test, expect } from "bun:test";
import {
  roleChunk,
  contentChunk,
  reasoningChunk,
  toolCallsChunk,
  finishChunk,
  usageChunk,
  errorChunk,
  sseLine,
  sseResponse,
} from "../common/sse.mjs";
import { isNetworkError, sseLines, guardStream, streamTimeoutMessage, intOption, readErrorText } from "../common/http.mjs";

const ENC = new TextEncoder();

async function collect(events, opts = {}) {
  const resp = sseResponse(events, { model: "m", ...opts });
  const text = await resp.text();
  const lines = text.split("\n\n").filter((l) => l.length);
  return { resp, text, lines };
}

function chunkShapes(lines) {
  return lines.map((l) => {
    if (l === "data: [DONE]") return "DONE";
    const v = JSON.parse(l.slice("data: ".length));
    if (v.error) return "error";
    if (v.usage) return "usage";
    const d = v.choices?.[0]?.delta ?? {};
    if (d.role === "assistant") return "role";
    if ("content" in d) return "content";
    if ("reasoning_content" in d) return "reasoning";
    if ("tool_calls" in d) return "tool_calls";
    const fr = v.choices?.[0]?.finish_reason;
    if (fr) return `finish:${fr}`;
    return "other";
  });
}

describe("chunk 形状", () => {
  const id = "chatcmpl-abc";
  const created = 1700000000;

  test("roleChunk 含 content:\"\"", () => {
    const v = roleChunk(id, created, "m");
    expect(v.choices).toEqual([{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }]);
    expect(v.object).toBe("chat.completion.chunk");
    expect(v.created).toBe(created);
  });

  test("content/reasoning/toolCalls/finish 形状", () => {
    expect(contentChunk(id, created, "m", "hi").choices[0].delta).toEqual({ content: "hi" });
    expect(reasoningChunk(id, created, "m", "think").choices[0].delta).toEqual({ reasoning_content: "think" });
    const tc = [{ index: 0, id: "call_1" }];
    expect(toolCallsChunk(id, created, "m", tc).choices[0].delta).toEqual({ tool_calls: tc });
    expect(finishChunk(id, created, "m", "stop").choices[0]).toEqual({ index: 0, delta: {}, finish_reason: "stop" });
  });

  test("usageChunk choices 为空、顶层 usage", () => {
    const v = usageChunk(id, created, "m", { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 });
    expect(v.choices).toEqual([]);
    expect(v.usage).toEqual({ prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 });
    const zero = usageChunk(id, created, "m", null);
    expect(zero.usage).toEqual({ prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 });
  });

  test("errorChunk 形状与 SSE 行编码", () => {
    expect(errorChunk("boom")).toEqual({ error: { message: "boom", type: "upstream_error", code: "upstream_error" } });
    expect(sseLine(errorChunk("boom"))).toBe(`data: ${JSON.stringify(errorChunk("boom"))}\n\n`);
  });
});

describe("渲染时序", () => {
  test("正常流：role 首块 → 内容 → finish → [DONE]；无 include_usage 无 usage 块", async () => {
    const { lines } = await collect([
      { type: "content", text: "你" },
      { type: "content", text: "好" },
      { type: "usage", usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 } },
      { type: "finish", reason: "stop" },
    ]);
    expect(chunkShapes(lines)).toEqual(["role", "content", "content", "finish:stop", "DONE"]);
  });

  test("usage 只在 include_usage 时发（全 0 也发），且在 finish 之后", async () => {
    const evs = [
      { type: "content", text: "x" },
      { type: "usage", usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 } },
      { type: "finish", reason: "stop" },
    ];
    const without = await collect(evs);
    expect(chunkShapes(without.lines)).toEqual(["role", "content", "finish:stop", "DONE"]);
    const withU = await collect(evs, { includeUsage: true });
    expect(chunkShapes(withU.lines)).toEqual(["role", "content", "finish:stop", "usage", "DONE"]);
  });

  test("上游无 finish → 补 stop；不带 include_usage 时 usage 不发", async () => {
    const { lines } = await collect([
      { type: "content", text: "a" },
      { type: "usage", usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } },
      { type: "end" },
    ]);
    expect(chunkShapes(lines)).toEqual(["role", "content", "finish:stop", "DONE"]);
  });

  test("背压：下游不读时不整段消费上游事件（只预取 role 块）", async () => {
    let produced = 0;
    async function* events() {
      for (let i = 0; i < 100; i++) {
        produced++;
        yield { type: "content", text: String(i) };
      }
    }
    const resp = sseResponse(events(), { model: "m" });
    await Bun.sleep(30);
    expect(produced).toBeLessThanOrEqual(1); // 有界预取：没人读时最多预取首块
    const reader = resp.body.getReader();
    await reader.read(); // role 块
    await Bun.sleep(10);
    expect(produced).toBeLessThanOrEqual(1); // 读一块才取一块
    await reader.read();
    expect(produced).toBeLessThanOrEqual(2);
    await reader.cancel();
  });

  test("错误：errorChunk 后停止，但仍发 [DONE]", async () => {
    const { lines } = await collect([
      { type: "content", text: "前半" },
      { type: "error", message: "上游错误" },
      { type: "content", text: "不应出现" },
    ]);
    expect(chunkShapes(lines)).toEqual(["role", "content", "error", "DONE"]);
  });

  test("错误后仍不发 stop，但 include_usage 时仍发 usage（与上游一致）", async () => {
    const { lines } = await collect(
      [
        { type: "content", text: "x" },
        { type: "usage", usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } },
        { type: "error", message: "boom" },
      ],
      { includeUsage: true },
    );
    expect(chunkShapes(lines)).toEqual(["role", "content", "error", "usage", "DONE"]);
  });

  test("上游马上出错：role 首块仍然先发（无条件）", async () => {
    const { lines } = await collect([{ type: "error", message: "x" }]);
    expect(chunkShapes(lines)).toEqual(["role", "error", "DONE"]);
  });

  test("思考与工具调用事件按序渲染", async () => {
    const { lines } = await collect([
      { type: "reasoning", text: "想" },
      { type: "tool_calls", toolCalls: [{ index: 0, id: "c1" }] },
      { type: "finish", reason: "tool_calls" },
    ]);
    expect(chunkShapes(lines)).toEqual(["role", "reasoning", "tool_calls", "finish:tool_calls", "DONE"]);
  });

  test("响应头：text/event-stream + no-store", async () => {
    const { resp } = await collect([{ type: "end" }]);
    expect(resp.headers.get("content-type")).toBe("text/event-stream");
    expect(resp.headers.get("cache-control")).toBe("no-store");
  });
});

// ---------------- 流读写层 ----------------

// 造一个响应体：按顺序吐 chunks；hang = 吐完后挂住（读一直悬着）
function bodyOf(chunks, { hang = false } = {}) {
  return new Response(
    new ReadableStream({
      async pull(controller) {
        if (chunks.length) return controller.enqueue(ENC.encode(chunks.shift()));
        if (hang) return new Promise(() => {});
        return controller.close();
      },
    }),
    { headers: { "content-type": "text/event-stream" } },
  );
}

// 事件流：数组里 Error 的项在产出时抛出（模拟连接断开 / 超时）
async function* gen(items, hooks = {}) {
  try {
    for (const it of items) {
      if (it instanceof Error) throw it;
      yield it;
    }
  } finally {
    hooks.finalized = true;
  }
}

const outcomeOf = async (iterable) => {
  const got = [];
  try {
    for await (const x of iterable) got.push(x);
    return { got, ended: true };
  } catch (e) {
    return { got, ended: false, error: e };
  }
};

describe("渲染：上游事件流出错与调用方断开", () => {
  test("事件流抛超时 → errorChunk（上游原文案）后仍发 usage 与 [DONE]，不补 stop", async () => {
    const timeout = Object.assign(new Error("上游流超过 180s 无数据"), { name: "TimeoutError" });
    const { lines, text } = await collect(gen([{ type: "content", text: "a" }, timeout]), { includeUsage: true });
    expect(chunkShapes(lines)).toEqual(["role", "content", "error", "usage", "DONE"]);
    expect(text).toContain("上游流超过 180s 无数据");
    expect(text).not.toContain('"finish_reason":"stop"');
  });

  test("事件流因别的原因中断 → errorChunk 带「上游请求失败」前缀", async () => {
    const { lines, text } = await collect(gen([new Error("connection reset")]));
    expect(chunkShapes(lines)).toEqual(["role", "error", "DONE"]);
    expect(text).toContain("上游请求失败: connection reset");
  });

  test("调用方 abort：停手后不再往下游写（无 stop、无 [DONE]），上游 generator 被关闭", async () => {
    const ctrl = new AbortController();
    const hooks = { finalized: false };
    async function* events() {
      try {
        yield { type: "content", text: "a" };
        ctrl.abort();
        yield { type: "content", text: "b" };
      } finally {
        hooks.finalized = true;
      }
    }
    const resp = sseResponse(events(), { model: "m", signal: ctrl.signal });
    const text = await resp.text();
    expect(chunkShapes(text.split("\n\n").filter((l) => l.length))).toEqual(["role", "content"]);
    expect(text).not.toContain("[DONE]");
    for (let i = 0; i < 40 && !hooks.finalized; i++) await Bun.sleep(5); // 下游关闭与 generator 收尾不分先后
    expect(hooks.finalized).toBe(true);
  });

  test("error 事件后同样关闭上游 generator（finally 执行），且不再取后续事件", async () => {
    let finalized = false;
    let pulled = 0;
    async function* events() {
      try {
        pulled++;
        yield { type: "content", text: "a" };
        pulled++;
        yield { type: "error", message: "boom" };
        pulled++;
        yield { type: "content", text: "不应出现" };
      } finally {
        finalized = true;
      }
    }
    const { lines, text } = await collect(events());
    expect(chunkShapes(lines)).toEqual(["role", "content", "error", "DONE"]);
    expect(text).not.toContain("不应出现");
    for (let i = 0; i < 20 && !finalized; i++) await Bun.sleep(5);
    expect(finalized).toBe(true);
    expect(pulled).toBe(2); // 第三个事件没被取
  });

  test("下游 cancel：调用 cancelUpstream；上游因此中断时错误被吞掉（不是上游的错）", async () => {
    let aborted = 0;
    let rejectWait;
    const hooks = { finalized: false };
    async function* events() {
      try {
        yield { type: "content", text: "a" };
        await new Promise((_, reject) => (rejectWait = reject)); // 等下一个数据块
      } finally {
        hooks.finalized = true;
      }
    }
    const resp = sseResponse(events(), {
      model: "m",
      cancelUpstream: () => {
        aborted++;
        rejectWait(new DOMException("The operation was aborted", "AbortError"));
      },
    });
    const reader = resp.body.getReader();
    await reader.read(); // role
    await reader.read(); // content
    await reader.cancel("client gone");
    expect(aborted).toBe(1);
    for (let i = 0; i < 40 && !hooks.finalized; i++) await Bun.sleep(5);
    expect(hooks.finalized).toBe(true);
  });

  test("请求开始前调用方已 abort：什么都不输出", async () => {
    const ctrl = AbortSignal.abort();
    const resp = sseResponse([{ type: "content", text: "a" }], { model: "m", signal: ctrl });
    expect(await resp.text()).toBe("");
  });
});

describe("sseLines：行批次与超时", () => {
  test("同一网络块里的多行作为一批产出；末尾无换行的残行不处理", async () => {
    const batches = [];
    for await (const b of sseLines(bodyOf(["data: 1\r\ndata: 2\n", "data: 3"]), { firstByteMs: 5000, idleMs: 5000 })) batches.push(b);
    expect(batches).toEqual([["data: 1", "data: 2"]]);
  });

  test("空闲超时抛 TimeoutError——不是正常结束", async () => {
    const out = await outcomeOf(sseLines(bodyOf(["data: 1\n"], { hang: true }), { firstByteMs: 5000, idleMs: 150 }));
    expect(out.got).toEqual([["data: 1"]]);
    expect(out.ended).toBe(false);
    expect(out.error.name).toBe("TimeoutError");
    expect(out.error.message).toBe("上游流超过 150ms 无数据");
  });

  test("首字节超时同样抛 TimeoutError", async () => {
    const out = await outcomeOf(sseLines(bodyOf([], { hang: true }), { firstByteMs: 120, idleMs: 5000 }));
    expect(out.ended).toBe(false);
    expect(out.error.name).toBe("TimeoutError");
  });

  test("提前离开（finish 后收尾）会取消上游读", async () => {
    let cancelled = false;
    const body = new Response(
      new ReadableStream({
        pull(controller) {
          controller.enqueue(ENC.encode("data: 1\n"));
          return new Promise(() => {});
        },
        cancel() {
          cancelled = true;
        },
      }),
    );
    for await (const _ of sseLines(body, { firstByteMs: 5000, idleMs: 5000 })) break; // 拿到第一批就走
    for (let i = 0; i < 40 && !cancelled; i++) await Bun.sleep(5);
    expect(cancelled).toBe(true);
  });

  test("超时文案", () => {
    expect(streamTimeoutMessage(180000)).toBe("上游流超过 180s 无数据");
    expect(streamTimeoutMessage(400)).toBe("上游流超过 400ms 无数据");
  });
});

describe("guardStream：透传看门狗", () => {
  const dec = (v) => new TextDecoder().decode(v);

  test("按块原样透传；下游暂停读取（背压）期间不计时，不误报", async () => {
    const reader = guardStream(bodyOf(["a", "b", "c"]).body, { firstMs: 60, idleMs: 60 }).getReader();
    expect(dec((await reader.read()).value)).toBe("a");
    await Bun.sleep(250); // 远超空闲阈值，但没有在等上游
    expect(dec((await reader.read()).value)).toBe("b");
    expect(dec((await reader.read()).value)).toBe("c");
    expect((await reader.read()).done).toBe(true);
  });

  test("等上游超过空闲阈值 → 以 TimeoutError 出错", async () => {
    const reader = guardStream(bodyOf(["a"], { hang: true }).body, { firstMs: 5000, idleMs: 150 }).getReader();
    expect(dec((await reader.read()).value)).toBe("a");
    const err = await reader.read().then(
      () => null,
      (e) => e,
    );
    expect(err?.name).toBe("TimeoutError");
    expect(err?.message).toBe("上游流超过 150ms 无数据");
  });

  test("首块超时", async () => {
    const reader = guardStream(bodyOf([], { hang: true }).body, { firstMs: 120, idleMs: 5000 }).getReader();
    const err = await reader.read().then(
      () => null,
      (e) => e,
    );
    expect(err?.name).toBe("TimeoutError");
  });

  test("下游取消 → 向上游传播", async () => {
    let cancelled = false;
    const src = new Response(
      new ReadableStream({
        pull() {
          return new Promise(() => {});
        },
        cancel() {
          cancelled = true;
        },
      }),
    );
    const reader = guardStream(src.body, { firstMs: 5000, idleMs: 5000 }).getReader();
    const pending = reader.read();
    await reader.cancel("client gone");
    expect((await pending).done).toBe(true);
    expect(cancelled).toBe(true);
  });

  test("上游自己出错：原样抛出", async () => {
    const failure = new Error("boom");
    const src = new Response(
      new ReadableStream({
        pull(controller) {
          controller.error(failure);
        },
      }),
    );
    const err = await guardStream(src.body, { firstMs: 5000, idleMs: 5000 }).getReader().read().then(
      () => null,
      (e) => e,
    );
    expect(err).toBe(failure);
  });
});

describe("网络错误识别与配置取值", () => {
  test("拒连 / 重置 / DNS / Bun 原生拼写 / 超时 都算网络错误", () => {
    for (const code of ["ECONNREFUSED", "ECONNRESET", "ENOTFOUND", "GetDnsFailed", "ConnectionRefused", "ConnectTimeout"]) {
      expect(isNetworkError(Object.assign(new TypeError("x"), { code }))).toBe(true);
    }
    expect(isNetworkError(Object.assign(new Error("x"), { code: "ECONNRESET" }))).toBe(true); // code 认得就不看类型
    expect(isNetworkError(Object.assign(new Error("x"), { name: "TimeoutError" }))).toBe(true);
    expect(isNetworkError(new TypeError("Unable to connect. Is the computer able to access the url?"))).toBe(true);
    expect(isNetworkError(new TypeError("ECONNRESET: The socket connection was closed unexpectedly."))).toBe(true);
  });

  test("调用方 abort 不算；其它错误不算", () => {
    expect(isNetworkError(new DOMException("aborted", "AbortError"), AbortSignal.abort())).toBe(false);
    expect(isNetworkError(new Error("boom"))).toBe(false);
    expect(isNetworkError(new TypeError("Invalid URL"))).toBe(false);
    expect(isNetworkError(undefined)).toBe(false);
  });

  test("intOption：正整数生效，非法值回落默认并封顶 24 小时", () => {
    expect(intOption(150, 1000)).toBe(150);
    expect(intOption("2000", 1000)).toBe(2000);
    expect(intOption(0, 1000)).toBe(1000);
    expect(intOption(0.5, 1000)).toBe(1000); // floor 后是 0 会让 setTimeout 立刻超时
    expect(intOption(-5, 1000)).toBe(1000);
    expect(intOption("abc", 1000)).toBe(1000);
    expect(intOption(Infinity, 1000)).toBe(1000);
    expect(intOption(undefined, 1000)).toBe(1000);
    expect(intOption(1e12, 1000)).toBe(24 * 3600 * 1000);
  });
});

describe("readErrorText：错误体的总限时与限长", () => {
  test("单块超大也只留 limit（累积文本不超过 limit）", async () => {
    const big = new Response(
      new ReadableStream({
        start(c) {
          c.enqueue(ENC.encode("a".repeat(100000)));
          c.close();
        },
      }),
    );
    expect(await readErrorText(big, { timeoutMs: 1000, limit: 16 })).toBe("a".repeat(16));
  });

  test("慢滴 body：限时是总时长，不被每块续命", async () => {
    const slow = new Response(
      new ReadableStream({
        async pull(c) {
          await Bun.sleep(100);
          c.enqueue(ENC.encode("x"));
        },
      }),
    );
    const t = Date.now();
    const text = await readErrorText(slow, { timeoutMs: 150, limit: 1024 });
    const took = Date.now() - t;
    expect(took).toBeLessThan(600); // 限时是总时长，不随数据块续期
    expect(text.length).toBeLessThan(10);
  });

  test("正常 body：读完返回全文（不超过 limit）", async () => {
    const ok = new Response(
      new ReadableStream({
        start(c) {
          c.enqueue(ENC.encode("hello "));
          c.enqueue(ENC.encode("world"));
          c.close();
        },
      }),
    );
    expect(await readErrorText(ok, { limit: 1024 })).toBe("hello world");
  });
});


// OpenAI chunk 构造 + SSE 行编码 + 渲染时序。

import { randomBytes } from "node:crypto";

// chunk 公共基底：{id, object, created, model, choices}；id = "chatcmpl-"+24hex，
// created 是秒。
function chunkId() {
  return "chatcmpl-" + randomBytes(12).toString("hex");
}

function chunkBase(id, created, model) {
  return { id, object: "chat.completion.chunk", created, model, choices: [] };
}

export function roleChunk(id, created, model) {
  const base = chunkBase(id, created, model);
  base.choices = [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }];
  return base;
}

export function contentChunk(id, created, model, content) {
  const base = chunkBase(id, created, model);
  base.choices = [{ index: 0, delta: { content }, finish_reason: null }];
  return base;
}

export function reasoningChunk(id, created, model, reasoning) {
  const base = chunkBase(id, created, model);
  base.choices = [{ index: 0, delta: { reasoning_content: reasoning }, finish_reason: null }];
  return base;
}

// toolCalls 是上游原值（choices[].delta.tool_calls 原样透传）。
export function toolCallsChunk(id, created, model, toolCalls) {
  const base = chunkBase(id, created, model);
  base.choices = [{ index: 0, delta: { tool_calls: toolCalls }, finish_reason: null }];
  return base;
}

export function finishChunk(id, created, model, finishReason) {
  const base = chunkBase(id, created, model);
  base.choices = [{ index: 0, delta: {}, finish_reason: finishReason }];
  return base;
}

// usage 挂在顶层，choices 为空数组。
export function usageChunk(id, created, model, usage) {
  const base = chunkBase(id, created, model);
  base.choices = [];
  base.usage = {
    prompt_tokens: usage?.prompt_tokens ?? 0,
    completion_tokens: usage?.completion_tokens ?? 0,
    total_tokens: usage?.total_tokens ?? 0,
  };
  return base;
}

// SSE 错误载荷（流已开始后无法再改状态码，按事件下发）。
export function errorChunk(message) {
  return { error: { message, type: "upstream_error", code: "upstream_error" } };
}

// SSE 行："data: " + JSON + "\n\n"
export function sseLine(v) {
  return `data: ${JSON.stringify(v)}\n\n`;
}

export function sseDone() {
  return "data: [DONE]\n\n";
}

export function sseHeaders() {
  return {
    "content-type": "text/event-stream",
    "cache-control": "no-store",
  };
}

// 统一事件流 → SSE Response。事件为
// {type: "content"|"reasoning"|"tool_calls"|"finish"|"usage"|"error"|"end", ...}，
// 事件源是数组或 async iterator。
//
// 渲染规则：
//   1. 首次读取先发 roleChunk，与上游是否出错无关
//   2. finish 事件立即发 finishChunk；usage 事件暂存，结束时再发
//   3. 结束时：没有错误且没有 finish → 补 finishChunk("stop")；
//      请求带 stream_options.include_usage 才发 usageChunk（全 0 也发）；
//      最后发 data: [DONE]，出错后也一样
//   4. 事件源抛错（连接断开 / 空闲超时）或给出 error 事件：发 errorChunk 后结束，
//      下游不会只看到连接被断开
//   5. signal abort（调用方取消）：停止向下游写，并调用事件源的 return()
//   6. 下游 cancel（客户端断开而宿主没有 abort signal）：除上述之外调用 cancelUpstream，
//      不等空闲超时就断开上游
//
// pull 驱动：下游读一块才向事件源取一个事件，下游读得慢时生成内容不会堆积在内存里。
// 空闲计时由 sseLines 负责，只计等待上游的时间。
// cancelUpstream：下游取消时立即断开上游。事件源的 return() 排在挂起的 next()
// 之后，上游没有新数据时要等到空闲超时才会执行，所以需要单独的回调。
export function sseResponse(events, { model, includeUsage = false, signal, cancelUpstream } = {}) {
  const id = chunkId();
  const created = Math.floor(Date.now() / 1000);
  const encoder = new TextEncoder();
  let controllerRef = null;
  let closed = false;
  let ended = false;
  let firstPulled = false;
  let usage = null;
  let finishSeen = false;
  let errored = false;
  let iterator = null;

  const onAbort = () => {
    closed = true;
    try {
      controllerRef?.close();
    } catch {}
    // 事件源的 return() 触发它的 finally（断开上游读）；排在挂起的 next() 之后执行
    try {
      Promise.resolve(iterator?.return?.()).catch(() => {});
    } catch {}
  };
  if (signal?.aborted) closed = true;
  else signal?.addEventListener("abort", onAbort, { once: true });

  // 事件源 → 迭代器（数组等同步可迭代也支持）。
  const iteratorOf = () => {
    if (iterator) return iterator;
    if (events && typeof events[Symbol.asyncIterator] === "function") {
      iterator = events[Symbol.asyncIterator]();
    } else {
      const src = events && typeof events[Symbol.iterator] === "function" ? events[Symbol.iterator]() : [][Symbol.iterator]();
      iterator = {
        next: async () => src.next(),
        return: src.return ? async (v) => src.return(v) : undefined,
      };
    }
    return iterator;
  };

  const push = (controller, v) => {
    if (closed) return;
    try {
      controller.enqueue(encoder.encode(v));
    } catch {
      closed = true;
    }
  };

  // 收尾：补 stop（无错误且没有 finish）→ usage（include_usage）→ [DONE] → close；出错后同样发 usage 与 [DONE]。
  const finalize = (controller) => {
    if (ended) return;
    ended = true;
    signal?.removeEventListener("abort", onAbort);
    if (!errored && !finishSeen) push(controller, sseLine(finishChunk(id, created, model, "stop")));
    if (includeUsage) push(controller, sseLine(usageChunk(id, created, model, usage)));
    push(controller, sseDone());
    try {
      controller.close();
    } catch {}
    try {
      Promise.resolve(iterator?.return?.()).catch(() => {});
    } catch {}
  };

  const stream = new ReadableStream({
    async pull(controller) {
      controllerRef = controller;
      if (closed || ended) {
        try {
          controller.close();
        } catch {}
        return;
      }
      if (!firstPulled) {
        firstPulled = true;
        push(controller, sseLine(roleChunk(id, created, model)));
        return;
      }
      // 取事件直到有输出或收尾；usage/end 这类无输出的继续取下一个。
      for (;;) {
        if (closed) return;
        let r;
        try {
          r = await iteratorOf().next();
        } catch (e) {
          // 调用方已断开（closed）时不算上游错误、不再往下游写
          if (closed) return;
          errored = true;
          push(controller, sseLine(errorChunk(e?.name === "TimeoutError" ? e.message : `上游请求失败: ${e?.message ?? e}`)));
          finalize(controller);
          return;
        }
        if (closed) return;
        if (r.done) {
          finalize(controller);
          return;
        }
        const ev = r.value;
        if (!ev || typeof ev !== "object") continue;
        let out = null;
        switch (ev.type) {
          case "content":
            out = contentChunk(id, created, model, ev.text);
            break;
          case "reasoning":
            out = reasoningChunk(id, created, model, ev.text);
            break;
          case "tool_calls":
            out = toolCallsChunk(id, created, model, ev.toolCalls);
            break;
          case "finish":
            finishSeen = true;
            out = finishChunk(id, created, model, ev.reason);
            break;
          case "usage":
            usage = ev.usage;
            break;
          case "error":
            errored = true;
            out = errorChunk(ev.message);
            break;
          case "end":
            break;
        }
        if (out !== null) {
          push(controller, sseLine(out));
          if (ev.type === "error") finalize(controller);
          return;
        }
      }
    },
    cancel() {
      // 下游取消（客户端断开而宿主没有 abort signal）：断开上游，不等空闲超时
      closed = true;
      signal?.removeEventListener("abort", onAbort);
      try {
        cancelUpstream?.();
      } catch {}
      try {
        Promise.resolve(iterator?.return?.()).catch(() => {});
      } catch {}
    },
  });
  return new Response(stream, { headers: sseHeaders() });
}

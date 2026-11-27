// OpenAI 请求解析与上游 agent 请求构建（响应侧渲染在 common/sse.mjs）。
import { randomUUID } from "node:crypto";

// 解析调用方 OpenAI body（字符串或已解析对象）。严格校验只对 model/messages
// 生效，其余字段原样保留。
export function parseChatRequest(input) {
  let v;
  if (typeof input === "string") {
    try {
      v = JSON.parse(input);
    } catch {
      throw badRequest("请求体不是合法的 OpenAI 对话请求");
    }
  } else {
    v = input;
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) throw badRequest("请求体必须是 JSON 对象");
  if (typeof v.model !== "string" || !v.model.trim()) throw badRequest("缺少 model 字段");
  if (!Array.isArray(v.messages)) throw badRequest("缺少 messages 数组");
  // 消息必须是带字符串 role 的对象：否则 buildAgentRequest 会抛 TypeError，
  // 宿主按 5xx 处理并切换账号重试；请求格式错误应直接回 400。
  for (let i = 0; i < v.messages.length; i++) {
    const m = v.messages[i];
    if (!m || typeof m !== "object" || Array.isArray(m) || typeof m.role !== "string") {
      throw badRequest(`messages[${i}] 不是合法的消息对象（需要 role 字符串）`);
    }
  }
  return v;
}

function badRequest(message) {
  const e = new Error(message);
  e.kind = "BadRequest";
  e.signIn = "kept";
  e.httpStatus = 400;
  return e;
}

// content：字符串原样；null → 空串；数组/对象整体转 JSON 字符串（不抽取文本，
// 上游不支持图片输入）。
export function contentToText(content) {
  if (typeof content === "string") return content;
  if (content == null) return "";
  return JSON.stringify(content);
}

// 模型严格匹配：与 display_name 或 key 完全相等（大小写敏感）；未命中回 400，
// 错误信息里列出可用模型。
export function resolveModel(requested, models) {
  const hit = models.find((m) => m.displayName === requested || m.key === requested);
  if (hit) return hit;
  const available = models.map((m) => m.displayName).join(", ");
  throw badRequest(`未知模型 ${JSON.stringify(requested)}（严格匹配模式）。可用模型: ${available}`);
}

// include_usage：仅当请求带 stream_options.include_usage 才发 usageChunk。
export function includeUsage(req) {
  return req?.stream_options?.include_usage === true;
}

// 尾随的 system 消息重排（消息以 system 结尾时，上游可能返回空流）：
// 1. 开头连续的 system 保持不动
// 2. 从末尾往前数的连续 system（保持相对顺序）挪到开头 system 之后
// 3. 夹在中间的 system 不动
// 4. [S1,U,A,S2] → [S1,S2,U,A]；[S1,U1,S2,U2] 不变
// 5. 全是 system 时不重排
export function reorderTrailingSystem(messages) {
  const ordered = [];
  let head = 0;
  for (; head < messages.length; head++) {
    if (messages[head].role === "system") ordered.push(messages[head]);
    else break;
  }
  if (head >= messages.length) return ordered; // 全是 system：不重排
  const trailing = [];
  const rest = [];
  let inTrailing = true;
  for (let i = messages.length - 1; i >= head; i--) {
    const m = messages[i];
    if (inTrailing && m.role === "system") trailing.push(m);
    else {
      inTrailing = false;
      rest.push(m);
    }
  }
  rest.reverse();
  trailing.reverse();
  ordered.push(...trailing, ...rest);
  return ordered;
}

// 上游 agent_chat_generation 请求体，字段必须齐全。
export function buildAgentRequest(req, model, setId) {
  const messages = req.messages ?? [];
  let lastUser = null;
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i]?.role === "user") {
      lastUser = messages[i];
      break;
    }
  }
  const lastUserText = lastUser ? contentToText(lastUser.content) : "";

  const ordered = reorderTrailingSystem(messages);

  const wireMessages = ordered.map((m) => {
    // 消息只带 role/content/tool_calls/tool_call_id；tool_* 为 null 时不带该字段
    const obj = { role: m.role, content: contentToText(m.content) };
    if (m.tool_calls != null) obj.tool_calls = m.tool_calls;
    if (m.tool_call_id != null) obj.tool_call_id = m.tool_call_id;
    return obj;
  });

  return {
    request_id: randomUUID(),
    request_set_id: setId,
    chat_record_id: setId,
    stream: true, // 插件侧始终按流式处理
    chat_task: "FREE_INPUT",
    chat_context: {
      text: lastUserText,
      workspaceLanguages: null,
      language: "",
      localeLang: "",
      preferredLanguage: "",
      features: null,
      chatPrompt: "",
      imageUrls: null,
    },
    image_urls: null,
    is_reply: false,
    is_retry: false,
    session_id: randomUUID(),
    code_language: "",
    source: 1,
    version: "3",
    chat_prompt: "",
    parameters: null,
    aliyun_user_type: "enterprise_standard",
    task_definition_type: "system",
    session_type: "assistant",
    agent_id: "agent_common",
    task_id: "common",
    model_config: {
      key: model.key,
      display_name: model.displayName,
      model: "",
      format: "openai",
      is_vl: false,
      is_reasoning: false,
      api_key: "",
      url: "",
      source: "organization",
      max_input_tokens: model.maxInputTokens || 0,
      enable: false,
      price_factor: 0,
      original_price_factor: 0,
      is_default: false,
      is_new: false,
      exclude_tags: null,
      tags: null,
      icon: null,
      strategies: null,
    },
    messages: wireMessages,
    // 请求未带或为 null 时发 null；带 [] 则原样 []
    tools: req.tools == null ? null : req.tools,
  };
}

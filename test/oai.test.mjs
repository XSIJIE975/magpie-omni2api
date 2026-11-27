// OpenAI → 灵码 agent 翻译：尾随 system 重排、模型严格匹配、agent 请求形状。
import { describe, test, expect } from "bun:test";
import { parseChatRequest, resolveModel, buildAgentRequest, reorderTrailingSystem, contentToText, includeUsage } from "../lingma/oai.mjs";

const MODEL = { key: "org_glm-5_x", displayName: "m", category: "chat", maxInputTokens: 200000 };

describe("尾随 system 重排", () => {
  const roles = (messages) => reorderTrailingSystem(messages).map((m) => m.role);
  const S = (c) => ({ role: "system", content: c });
  const U = (c) => ({ role: "user", content: c });
  const A = (c) => ({ role: "assistant", content: c });

  test("[S1,U,A,S2] → [S1,S2,U,A]", () => {
    expect(roles([S("S1"), U("U"), A("A"), S("S2")])).toEqual(["system", "system", "user", "assistant"]);
    expect(reorderTrailingSystem([S("S1"), U("U"), A("A"), S("S2")]).map((m) => m.content)).toEqual(["S1", "S2", "U", "A"]);
  });

  test("[S1,U1,S2,U2] 原样不动（夹在中间的 system 不动）", () => {
    expect(roles([S("S1"), U("U1"), S("S2"), U("U2")])).toEqual(["system", "user", "system", "user"]);
  });

  test("[S1,S2] 全是 system：不重排", () => {
    expect(roles([S("S1"), S("S2")])).toEqual(["system", "system"]);
  });

  test("[U,S1,S2] 尾随连续 system 保持相对顺序前移", () => {
    expect(roles([U("U"), S("S1"), S("S2")])).toEqual(["system", "system", "user"]);
  });

  test("无 system：原样", () => {
    expect(roles([U("U"), A("A")])).toEqual(["user", "assistant"]);
  });
});

describe("模型严格匹配", () => {
  const models = [MODEL, { key: "org_ds_4", displayName: "DeepSeek-V4-Flash", category: "chat", maxInputTokens: 100000 }];

  test("display_name 命中", () => {
    expect(resolveModel("m", models).key).toBe("org_glm-5_x");
    expect(resolveModel("DeepSeek-V4-Flash", models).key).toBe("org_ds_4");
  });

  test("key 命中", () => {
    expect(resolveModel("org_glm-5_x", models).displayName).toBe("m");
  });

  test("大小写不同不命中 → 400 列出可用模型", () => {
    expect(() => resolveModel("M", models)).toThrow("严格匹配");
    expect(() => resolveModel("deepseek-v4-flash", models)).toThrow("可用模型");
  });

  test("未知模型 → 400", () => {
    let msg = "";
    try {
      resolveModel("gpt-4o", models);
    } catch (e) {
      msg = e.message;
    }
    expect(msg).toContain("gpt-4o");
    expect(msg).toContain("m");
    expect(msg).toContain("DeepSeek-V4-Flash");
  });
});

describe("agent 请求构建", () => {
  test("chat_context.text 取最后一条 user；content 数组整体转 JSON 字符串", () => {
    const req = parseChatRequest(
      JSON.stringify({
        model: "m",
        messages: [
          { role: "system", content: "S" },
          { role: "user", content: [{ type: "text", text: "第一" }, { type: "text", text: "第二" }] },
          { role: "assistant", content: "A" },
          { role: "user", content: "最终问题" },
        ],
        stream: true,
      }),
    );
    const body = buildAgentRequest(req, MODEL, "set-1");
    expect(body.chat_context.text).toBe("最终问题");
    expect(body.messages[1].content).toBe(JSON.stringify([{ type: "text", text: "第一" }, { type: "text", text: "第二" }]));
  });

  test("形状：固定字段与 model_config", () => {
    const req = parseChatRequest(JSON.stringify({ model: "m", messages: [{ role: "user", content: "你好" }], stream: true }));
    const body = buildAgentRequest(req, MODEL, "set-1");
    expect(body.chat_task).toBe("FREE_INPUT");
    expect(body.stream).toBe(true);
    expect(body.request_set_id).toBe("set-1");
    expect(body.chat_record_id).toBe("set-1");
    expect(body.session_type).toBe("assistant");
    expect(body.task_definition_type).toBe("system");
    expect(body.task_id).toBe("common");
    expect(body.agent_id).toBe("agent_common");
    expect(body.source).toBe(1);
    expect(body.version).toBe("3");
    expect(body.aliyun_user_type).toBe("enterprise_standard");
    expect(body.chat_context).toBeTypeOf("object"); // 字符串会 NPE
    expect(body.model_config.key).toBe("org_glm-5_x");
    expect(body.model_config.display_name).toBe("m");
    expect(body.model_config.max_input_tokens).toBe(200000);
    expect(body.model_config.source).toBe("organization");
    expect(body.model_config.format).toBe("openai");
    // request_id / session_id 是 uuid
    expect(body.request_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(body.session_id).toMatch(/^[0-9a-f-]{36}$/);
  });

  test("tools：未带发 null；带 [] 原样；消息体只留四个字段", () => {
    const req = parseChatRequest(
      JSON.stringify({
        model: "m",
        messages: [
          { role: "user", content: "x", name: "ignored", extra: 1 },
          { role: "assistant", content: "", tool_calls: [{ index: 0, id: "c1" }] },
          { role: "tool", content: "res", tool_call_id: "c1" },
        ],
        tools: [],
      }),
    );
    const body = buildAgentRequest(req, MODEL, "s");
    expect(body.tools).toEqual([]);
    const msgs = body.messages;
    expect(Object.keys(msgs[0]).sort()).toEqual(["content", "role"]);
    expect(msgs[1].tool_calls).toEqual([{ index: 0, id: "c1" }]);
    expect(msgs[2].tool_call_id).toBe("c1");
    const req2 = parseChatRequest(JSON.stringify({ model: "m", messages: [{ role: "user", content: "x" }] }));
    expect(buildAgentRequest(req2, MODEL, "s").tools).toBe(null);
  });

  test("显式的 null 不写字段（上游不序列化值为 null 的可选字段）；tool_call_id null 同理", () => {
    const req = parseChatRequest(
      JSON.stringify({
        model: "m",
        messages: [
          { role: "user", content: "x", tool_calls: null, tool_call_id: null },
          { role: "assistant", content: "", tool_calls: null },
          { role: "tool", content: "r", tool_call_id: "c9" },
        ],
      }),
    );
    const msgs = buildAgentRequest(req, MODEL, "s").messages;
    expect(msgs[0]).toEqual({ role: "user", content: "x" });
    expect(msgs[1]).toEqual({ role: "assistant", content: "" });
    expect(msgs[2]).toEqual({ role: "tool", content: "r", tool_call_id: "c9" });
  });

  test("contentToText 与 includeUsage", () => {
    expect(contentToText("s")).toBe("s");
    expect(contentToText(null)).toBe("");
    expect(contentToText([{ a: 1 }])).toBe('[{"a":1}]');
    expect(includeUsage({ stream_options: { include_usage: true } })).toBe(true);
    expect(includeUsage({ stream_options: {} })).toBe(false);
    expect(includeUsage({})).toBe(false);
  });
});

describe("parseChatRequest 校验", () => {
  test("非 JSON / 非 model / 非 messages → 400 类错误", () => {
    expect(() => parseChatRequest("not json")).toThrow();
    expect(() => parseChatRequest("{}")).toThrow();
    expect(() => parseChatRequest(JSON.stringify({ model: "m" }))).toThrow();
    expect(() => parseChatRequest(JSON.stringify({ model: "", messages: [] }))).toThrow();
    const ok = parseChatRequest(JSON.stringify({ model: "m", messages: [], anything: "else" }));
    expect(ok.anything).toBe("else");
  });
});

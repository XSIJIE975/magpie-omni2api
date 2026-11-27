// customB64 编解码：往返与边界用例。
import { describe, test, expect } from "bun:test";
import { encode, decode } from "../lingma/codec.mjs";

const ENCODED =
  /^[_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!$]*$/;

describe("customB64 codec", () => {
  test("roundtrip：空串 / 单字节 / 长度整除与不整除 / 多字节字符", () => {
    for (const s of ["", "a", "ab", "abc", "abcd", "hello, 世界", '{"payload":"x"}', "x".repeat(1000)]) {
      const wire = encode(Buffer.from(s, "utf8"));
      expect(decode(wire).toString("utf8")).toBe(s);
    }
  });

  test("确定性与字母表：同一输入编码相同，输出只含自定义字母表与 $ 填充", () => {
    const buf = Buffer.from("the quick brown fox jumps over the lazy dog", "utf8");
    const a = encode(buf);
    expect(encode(buf)).toBe(a);
    expect(a).toMatch(ENCODED);
  });

  test("解码剥 \\r \\n，但 $ 填充参与交换", () => {
    const plain = "pad: 你好"; // 11 字节：编码后带一个 $ 填充
    const wire = encode(Buffer.from(plain, "utf8"));
    expect(wire).toContain("$");
    const withBreaks = wire.slice(0, 10) + "\r\n" + wire.slice(10);
    expect(decode(withBreaks).toString("utf8")).toBe(plain);
    expect(decode(wire).toString("utf8")).toBe(plain);
  });

  test("长度不被 3 整除的输入全部可逆（0–40 字节）", () => {
    for (let n = 0; n < 40; n++) {
      const buf = Buffer.alloc(n, 0x61);
      expect(decode(encode(buf)).toString("latin1")).toBe(buf.toString("latin1"));
    }
  });
});

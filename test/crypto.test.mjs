// 固定向量与密码学形状：云伴签名固定向量、RSA 双实现、PKCE、脱敏。
import { describe, test, expect } from "bun:test";
import { generateKeyPairSync, publicEncrypt, constants as cryptoConstants } from "node:crypto";
import { sha256hex, hmacSha256Hex, redact, scrubValues } from "../common/http.mjs";
import {
  generatePkce,
  parseSpkiPem,
  rsaEncryptBigInt,
  temporaryKey,
  RSA_PUBLIC_KEY_PEM,
} from "../lingma/crypto.mjs";

describe("云伴签名固定向量", () => {
  test("cbdd0d8d…304438", () => {
    const canonical = `POST\n/me\n${sha256hex("")}\n1700000000000\nfixed-nonce`;
    expect(canonical).toBe(
      "POST\n/me\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n1700000000000\nfixed-nonce",
    );
    expect(hmacSha256Hex("test-key", canonical)).toBe(
      "cbdd0d8d0985d6e3abc9a01b9092790862aeed27acd89de1b6a142a014304438",
    );
  });

  test("换 nonce 后签名必须不同（防重放基础）", () => {
    const canonical = `POST\n/me\n${sha256hex("")}\n1700000000000\nother-nonce`;
    expect(hmacSha256Hex("test-key", canonical)).not.toBe(
      "cbdd0d8d0985d6e3abc9a01b9092790862aeed27acd89de1b6a142a014304438",
    );
  });
});

describe("RSA 双实现", () => {
  // 用测试密钥对验证可解性。运行时的 OpenSSL 策略可能禁用
  // privateDecrypt + RSA_PKCS1_PADDING，所以解密侧用 BigInt 模幂（c^d mod n）验证。
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const jwk = publicKey.export({ format: "jwk" });
  const n = BigInt("0x" + Buffer.from(jwk.n, "base64url").toString("hex"));
  const e = BigInt("0x" + Buffer.from(jwk.e, "base64url").toString("hex"));
  const d = BigInt("0x" + Buffer.from(privateKey.export({ format: "jwk" }).d, "base64url").toString("hex"));
  const K = Buffer.from("0123456789abcdef", "utf8"); // 16 字节

  function modPow(b, ex, m) {
    let r = 1n;
    b %= m;
    while (ex > 0n) {
      if (ex & 1n) r = (r * b) % m;
      b = (b * b) % m;
      ex >>= 1n;
    }
    return r;
  }

  // PKCS#1 v1.5 解包：去掉 0x00 0x02 PS 0x00 前缀
  function pkcs1Unpad(ct) {
    const em = Buffer.from(modPow(BigInt("0x" + Buffer.from(ct).toString("hex")), d, n).toString(16).padStart(256, "0"), "hex");
    const sep = em.indexOf(0, 2);
    return em.subarray(sep + 1);
  }

  test("BigInt 路径：128 字节，能解回 K", () => {
    const ct = rsaEncryptBigInt(n, e, K);
    expect(ct.length).toBe(128);
    expect(pkcs1Unpad(ct).toString()).toBe(K.toString());
  });

  test("node:crypto 路径（与 rsaEncryptKey 同款调用）：128 字节，能解回 K", () => {
    // 与 lingma/crypto.mjs 的 rsaEncryptKey 相同的调用形状
    const ct = publicEncrypt({ key: publicKey, padding: cryptoConstants.RSA_PKCS1_PADDING }, K);
    expect(ct.length).toBe(128);
    expect(pkcs1Unpad(ct).toString()).toBe(K.toString());
  });

  test("内嵌公钥 SPKI 解析：1024 位模数", () => {
    const { n: N, e: E } = parseSpkiPem(RSA_PUBLIC_KEY_PEM);
    expect((N.toString(2).length + 7) >> 3).toBe(128);
    expect(E).toBe(65537n);
  });
});

describe("PKCE（非标准：b64url(hex(sha256(verifier))) → 86 字符）", () => {
  test("verifier 43 字符、challenge 86 字符", () => {
    const { verifier, challenge } = generatePkce();
    expect(verifier.length).toBe(43);
    expect(challenge.length).toBe(86);
  });

  test("challenge 由 verifier 的 sha256 hex 推得", () => {
    const { verifier, challenge } = generatePkce();
    const expectChallenge = Buffer.from(sha256hex(verifier), "ascii").toString("base64url");
    expect(challenge).toBe(expectChallenge);
  });
});

describe("temporaryKey 语义", () => {
  test("取 hex 字符串前 16 个 ASCII 字符（不是 digest 前 16 字节）", () => {
    const K = temporaryKey("mid", "uid");
    expect(K.length).toBe(16);
    const hex = sha256hex("lingma-aes-v1miduidlingma-secure-salt-2024");
    expect(K.toString("ascii")).toBe(hex.slice(0, 16));
    // 前 16 字节（错误实现）会与正确值不同
    expect(K.toString("hex")).not.toBe(hex.slice(0, 32));
  });
});

describe("日志脱敏", () => {
  test("token / sessionKey / password / authorization 替换为 ***", () => {
    const s = JSON.stringify({
      token: "t-secret",
      sessionKey: "sk-secret",
      password: "pw-secret",
      authorization: "Bearer abc.def",
      refreshToken: "r-secret",
      name: "张三",
    });
    const out = redact(s);
    expect(out).not.toContain("t-secret");
    expect(out).not.toContain("sk-secret");
    expect(out).not.toContain("pw-secret");
    expect(out).not.toContain("r-secret");
    expect(out).not.toContain("abc.def");
    expect(out).toContain("张三");
  });

  test("Bearer / Basic 头脱敏（authorization 整体擦掉）", () => {
    expect(redact("authorization: Bearer COSY.abc.123")).toBe("authorization=***");
    expect(redact("authorization: Basic dXNlcjpwYXNz")).toBe("authorization=***");
  });

  test("转义 JSON / 头式键 / encryptUserInfo / 自由文本 token 也脱敏", () => {
    expect(redact('{\\"token\\": \\"abc-123\\"}')).not.toContain("abc-123");
    expect(redact('{"encryptUserInfo":"eui-secret"}')).not.toContain("eui-secret");
    expect(redact("cosy-key: k-secret")).not.toContain("k-secret");
    expect(redact("invalid token sk-abc")).not.toContain("sk-abc");
  });

  test("值级擦除：已知秘密按原值替换", () => {
    const out = scrubValues("failed with sect-1 and rt-1", ["sect-1", "rt-1"]);
    expect(out).not.toContain("sect-1");
    expect(out).not.toContain("rt-1");
  });
});

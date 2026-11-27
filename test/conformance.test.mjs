// 协议一致性：固定签名样本与独立实现的公式校验。
import { describe, test, expect } from "bun:test";
import { createHash, createDecipheriv } from "node:crypto";
import { aSignature, bSignature, bAuthorization, bPayloadB64, synthesizeMaterial } from "../lingma/crypto.mjs";

const md5 = (s) => createHash("md5").update(s).digest("hex");
const sha256hex = (s) => createHash("sha256").update(s).digest("hex");

// A 族签名的固定样本（签名只由日期与内嵌盐决定）。
const A_VECTORS = [
  ["Fri, 09 Oct 2026 04:30:39 GMT", "01ccd9f3813e17e890dfce5991f639f6"],
  ["Fri, 09 Oct 2026 04:30:41 GMT", "311035112450398670ee40e851e46fb6"],
  ["Fri, 09 Oct 2026 04:30:42 GMT", "83e0111fdb2b41dcbe696fcf37ef5b4e"],
  ["Fri, 09 Oct 2026 04:32:41 GMT", "d2d396360e38c301590f3c0ee4acdc01"],
  ["Fri, 09 Oct 2026 04:33:39 GMT", "acb9e9b86b954c0bbe06c083b4384d1c"],
  ["Fri, 09 Oct 2026 07:45:12 GMT", "1f3fff8c5167a770151eeb7e00286e69"],
  ["Fri, 09 Oct 2026 07:45:14 GMT", "d91c4d8ef3835d2a623669be9fbde28e"],
  ["Fri, 09 Oct 2026 07:47:13 GMT", "e82bc83424ea36217f44377484d49c27"],
  ["Fri, 09 Oct 2026 07:48:12 GMT", "e62623c24758f3ecbdc56edc05a8ad74"],
  ["Fri, 09 Oct 2026 07:49:13 GMT", "838f35073a485c748a49f8ee7ba70118"],
  ["Fri, 09 Oct 2026 07:51:13 GMT", "7d4c270a9705364bd66a70528dfa1623"],
  ["Fri, 09 Oct 2026 10:05:07 GMT", "4d82605f120206c5b98ea93a664f985b"],
  ["Fri, 09 Oct 2026 10:05:10 GMT", "63eb808240a3dfc61218ca6201a96c26"],
  ["Fri, 09 Oct 2026 10:02:02 GMT", "2be91965521491218564e9a80bf8407a"],
  ["Fri, 09 Oct 2026 10:02:04 GMT", "44d17f3cb6b484facb366453cbd56f6a"],
  ["Fri, 09 Oct 2026 10:02:05 GMT", "5d6ae2eaae44394ef5ff743017a416bb"],
  ["Fri, 09 Oct 2026 10:02:12 GMT", "48253bf6b6b470b5daa04e78d69b1c8b"],
];

describe("A 族签名固定样本", () => {
  for (const [date, sig] of A_VECTORS) {
    test(date, () => {
      expect(aSignature(date)).toBe(sig);
    });
  }
});

describe("B 族签名：与独立实现逐字符一致", () => {
  test("bSignature = md5(payload\\nkey\\nts\\nbody\\nsigpath)", () => {
    const payload = bPayloadB64("eui-sample", "req-123");
    const key = md5("test-key-material");
    const ts = "1790000000";
    const body = "wire-body-sample";
    const sigpath = "/api/v2/model/list";
    const expected = md5(`${payload}\n${key}\n${ts}\n${body}\n${sigpath}`);
    expect(bSignature(payload, key, ts, body, sigpath)).toBe(expected);
  });

  test("bPayload 键序与版本字段", () => {
    const p = bPayloadB64("EUI", "req-1");
    expect(Buffer.from(p, "base64").toString("utf8")).toBe(
      '{"cosyVersion":"3.4.0","ideVersion":"","info":"EUI","requestId":"req-1","version":"v1"}',
    );
  });

  test("authorization 形状：Bearer COSY.<payload>.<sig>", () => {
    const a = bAuthorization("payload-abc", "sig-def");
    expect(a).toBe("Bearer COSY.payload-abc.sig-def");
  });
});

describe("eui 合成：结构与独立解密回读", () => {
  const identity = {
    machineId: "0f0e0d0c-0b0a-4a49-8a79-6b5c4d3e2f10",
    uid: "11111111-2222-4333-8444-555555555555",
    name: "张三",
    orgId: "99999999-8888-4777-8666-555555555555",
    orgName: "示例组织",
  };

  test("确定性：同参数产出相同；key 为 172 字符 b64（128 字节 RSA 密文）", () => {
    const a = synthesizeMaterial(identity.machineId, identity.uid, identity.name, identity.orgId, identity.orgName);
    const b = synthesizeMaterial(identity.machineId, identity.uid, identity.name, identity.orgId, identity.orgName);
    expect(a.encryptUserInfo).toBe(b.encryptUserInfo);
    expect(a.key.length).toBe(172);
    expect(Buffer.from(a.key, "base64").length).toBe(128);
  });

  test("eui 可用独立实现的 AES-128-CBC 解出身份字段（key = iv）", () => {
    const { encryptUserInfo } = synthesizeMaterial(identity.machineId, identity.uid, identity.name, identity.orgId, identity.orgName);
    // 独立派生：sha256(...) 的 hex 前 16 个 ASCII 字符，不是 digest 前 16 字节
    const K = Buffer.from(sha256hex(`lingma-aes-v1${identity.machineId}${identity.uid}lingma-secure-salt-2024`).slice(0, 16), "ascii");
    const decipher = createDecipheriv("aes-128-cbc", K, K);
    const plain = Buffer.concat([decipher.update(Buffer.from(encryptUserInfo, "base64")), decipher.final()]).toString("utf8");
    const obj = JSON.parse(plain);
    expect(obj).toMatchObject({
      name: identity.name,
      uid: identity.uid,
      yx_uid: identity.uid,
      organization_id: identity.orgId,
      organization_name: identity.orgName,
    });
    expect(obj.security_oauth_token).toBe("");
    expect(obj.refresh_token).toBe("");
  });
});

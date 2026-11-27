// 灵码协议密码学：A 族签名、B 族 COSY Bearer 签名、RSA-1024 公钥（内嵌）、
// AES-128-CBC、会话材料合成、浏览器登录 PKCE。
import { createCipheriv, publicEncrypt, constants as cryptoConstants, randomBytes } from "node:crypto";
import { md5hex, sha256hex } from "../common/http.mjs";

export const A_SALT = "Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe";
export const COSY_VERSION = "3.4.0";

// 内嵌 RSA-1024 公钥。
export const RSA_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDyphB1FdbF8Meu+wwZksvfrsUB
zeY8ATqDvynWGE/Hd/hW9Hj6NE4yhIxSB1Zaeyuv8sxt8l3W7xlP6XpkOk6Pw5pZ
HVZpCElfeVZqamettW+nm5ZpFlDS/OXB2Pt+cewZ+jfsT383rth1xuQCWtjizep0
AJdUTZGyKXclY0Mt8wIDAQAB
-----END PUBLIC KEY-----`;

// ---------------- A 族签名（登录面） ----------------

// a_signature(date) = md5hex("cosy&&" + SALT + "&" + date)
export function aSignature(date) {
  return md5hex(`cosy&&${A_SALT}&${date}`);
}

// GMT 时间，格式 `Fri, 09 Oct 2026 04:30:39 GMT`。
export function httpDateNow() {
  return new Date().toUTCString();
}

// A 族请求头三元组：Date / Signature / Appcode。
export function aHeaders() {
  const date = httpDateNow();
  return [
    ["Date", date],
    ["Signature", aSignature(date)],
    ["Appcode", "cosy"],
  ];
}

// ---------------- B 族签名（会话面，COSY Bearer） ----------------

// payload 槽：b64std(json({cosyVersion, ideVersion, info, requestId, version}))，
// 键按字母序（JS 对象按插入顺序序列化）。
export function bPayloadB64(encryptUserInfo, requestId, cosyVersion = COSY_VERSION) {
  const s = JSON.stringify({
    cosyVersion,
    ideVersion: "",
    info: encryptUserInfo,
    requestId,
    version: "v1",
  });
  return Buffer.from(s, "utf8").toString("base64");
}

// b_signature = md5hex(payload + "\n" + key + "\n" + unix秒 + "\n" + 编码后body + "\n" + sigpath)
export function bSignature(payloadB64, key, unixTs, encodedBody, sigpath) {
  return md5hex(`${payloadB64}\n${key}\n${unixTs}\n${encodedBody}\n${sigpath}`);
}

// Authorization: Bearer COSY.<payload>.<sig>
export function bAuthorization(payloadB64, sig) {
  return `Bearer COSY.${payloadB64}.${sig}`;
}

// ---------------- 会话材料合成 ----------------

// 临时会话密钥：sha256("lingma-aes-v1" + machineId + uid + "lingma-secure-salt-2024")
// 的 hex 字符串前 16 个 ASCII 字符（不是 digest 的前 16 字节）。
export function temporaryKey(machineId, uid) {
  const hex = sha256hex(`lingma-aes-v1${machineId}${uid}lingma-secure-salt-2024`);
  return Buffer.from(hex.slice(0, 16), "ascii"); // 16 字节
}

// AES-128-CBC（key = iv）。node:crypto 默认已做 PKCS#7，不要手动补填充。
export function aesCbcEncrypt(key, plaintext) {
  const cipher = createCipheriv("aes-128-cbc", key, key);
  return Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
}

// encrypt_user_info 的明文：21 个字段，顺序与类型固定（expire_time 是数字 0、
// 三个布尔为 false、organization_tags 为 null、on_premise 是字符串 "true"）。
export function euiPlaintext(name, uid, orgId, orgName) {
  const esc = (s) => JSON.stringify(s);
  return (
    `{"name":${esc(name)},"aid":"","uid":${esc(uid)},"yx_uid":${esc(uid)},` +
    `"organization_id":${esc(orgId)},"organization_name":${esc(orgName)},` +
    `"staffId":"","avatar_url":"","security_oauth_token":"","refresh_token":"",` +
    `"expire_time":0,"key":"","encrypt_user_info":"","user_source_channel":"",` +
    `"user_type":"enterprise_standard","data_policy_agreed":false,"email":"",` +
    `"is_data_policy_modifiable":false,"is_quota_exceeded":false,` +
    `"organization_tags":null,"on_premise":"true"}`
  );
}

// ---------------- RSA（node:crypto，失败时用 BigInt 实现） ----------------

// 最小 SPKI DER 解析（不需要任何 OpenSSL 策略）：SEQ{SEQ{OID,NULL},BITSTRING{SEQ{INTEGER n, INTEGER e}}}
function readTlv(buf, off) {
  const tag = buf[off];
  let len = buf[off + 1];
  let head = 2;
  if (len & 0x80) {
    const nBytes = len & 0x7f;
    len = 0;
    for (let i = 0; i < nBytes; i++) len = len * 256 + buf[off + 2 + i];
    head = 2 + nBytes;
  }
  return { tag, start: off + head, end: off + head + len };
}

export function parseSpkiPem(pem) {
  const der = Buffer.from(
    pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
    "base64",
  );
  const top = readTlv(der, 0); // SEQUENCE
  const alg = readTlv(der, top.start); // AlgorithmIdentifier
  const bits = readTlv(der, alg.end); // BIT STRING
  const inner = readTlv(der, bits.start + 1); // 内容首字节是 unused-bits 计数
  const nInt = readTlv(der, inner.start);
  const eInt = readTlv(der, nInt.end);
  return {
    n: BigInt("0x" + Buffer.from(der.subarray(nInt.start, nInt.end)).toString("hex")),
    e: BigInt("0x" + Buffer.from(der.subarray(eInt.start, eInt.end)).toString("hex")),
  };
}

function modPow(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

// RSA-PKCS1v15 加密（纯 BigInt，OpenSSL 策略无关的兜底路径）。
export function rsaEncryptBigInt(n, e, data) {
  const k = (n.toString(2).length + 7) >> 3; // 模数字节数（1024 位 → 128）
  if (data.length > k - 11) throw new Error("rsa: message too long");
  const em = Buffer.alloc(k);
  em[1] = 2;
  let i = 2;
  while (i < k - data.length - 1) {
    let b;
    do {
      b = randomBytes(1)[0];
    } while (b === 0);
    em[i++] = b;
  }
  em[i++] = 0;
  Buffer.from(data).copy(em, i);
  const c = modPow(BigInt("0x" + em.toString("hex")), e, n);
  return Buffer.from(c.toString(16).padStart(k * 2, "0"), "hex");
}

// 加密 K 的 16 个原始字节（不是 hex 字符串）：先用 node:crypto，抛错时改用
// BigInt 实现（运行时的 OpenSSL 策略可能限制这种填充方式）。
export function rsaEncryptKey(K, log) {
  try {
    return publicEncrypt(
      { key: RSA_PUBLIC_KEY_PEM, padding: cryptoConstants.RSA_PKCS1_PADDING },
      K,
    );
  } catch (e) {
    log?.("warn", `node:crypto RSA 加密失败，改用 BigInt 实现: ${e?.message ?? e}`);
    const { n, e: exp } = parseSpkiPem(RSA_PUBLIC_KEY_PEM);
    return rsaEncryptBigInt(n, exp, K);
  }
}

// 合成整套 B 族会话材料：
//   encrypt_user_info = b64std(AES-128-CBC(eui 明文, key=K, iv=K))
//   key               = b64std(RSA-PKCS1v15(K, 内嵌公钥))
export function synthesizeMaterial(machineId, uid, name, orgId, orgName, log) {
  const K = temporaryKey(machineId, uid);
  const encryptUserInfo = aesCbcEncrypt(K, Buffer.from(euiPlaintext(name, uid, orgId, orgName), "utf8")).toString("base64");
  const key = rsaEncryptKey(K, log).toString("base64");
  return { key, encryptUserInfo };
}

// ---------------- 浏览器登录 PKCE ----------------

// verifier = b64url(32 随机字节)，43 字符；
// challenge = b64url(sha256hex(verifier) 的 64 字符 ASCII)，86 字符（不是 RFC 7636 的 43）。
export function generatePkce() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = Buffer.from(sha256hex(verifier), "ascii").toString("base64url");
  return { verifier, challenge };
}

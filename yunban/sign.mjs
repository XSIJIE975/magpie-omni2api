// 逐请求 HMAC-SHA256 签名：
// X-Banban-Signature = HMAC-SHA256(sessionKey, "{method}\n{path}\n{sha256hex(body)}\n{timestamp}\n{nonce}")
// timestamp 为毫秒时间戳，服务端只接受 ±5 分钟内的值；nonce 每次请求唯一（UUID）。
import { randomUUID } from "../common/http.mjs";
import { sha256hex, hmacSha256Hex } from "./crypto.mjs";

export { sha256hex, hmacSha256Hex };

// 返回 {timestamp, nonce, signature}。
export function signRequest(sessionKey, method, path, body) {
  const bytes = body ?? Buffer.alloc(0);
  const timestamp = Date.now().toString(); // 毫秒，13 位
  const nonce = randomUUID(); // 带连字符，36 字符
  const bodyHash = sha256hex(bytes); // 空体 = sha256("") = e3b0c442…b855
  const canonical = `${method}\n${path}\n${bodyHash}\n${timestamp}\n${nonce}`;
  const signature = hmacSha256Hex(sessionKey, canonical);
  return { timestamp, nonce, signature };
}

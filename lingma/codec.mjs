// 灵码接口的 customB64 编解码。
//
// 编码 = 标准 base64 位打包（自定义字母表，`$` 填充）→ 字符层首尾交换：
//   N = len(encoded); t = Math.floor(N / 3)
//   wire = enc[N-t..] + enc[t..N-t] + enc[..t]
// 交换是对合，解码用同一操作。

const ALPHABET = Buffer.from(
  "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!",
  "latin1",
);
const PAD = 0x24; // '$'

// 字符层首尾交换（对合，编码解码共用）。t 取整数除法的商。
function swapSegments(s) {
  const n = s.length;
  const t = Math.floor(n / 3);
  const out = new Uint8Array(n);
  const tail = s.subarray(n - t);
  const mid = s.subarray(t, n - t);
  const head = s.subarray(0, t);
  out.set(tail, 0);
  out.set(mid, t);
  out.set(head, n - t);
  return out;
}

// 标准 base64 位打包（MSB 在前）+ 自定义字母表，不含首尾交换。
function b64Core(data) {
  const out = new Uint8Array(Math.ceil(data.length / 3) * 4);
  let o = 0;
  const full = data.length - (data.length % 3);
  for (let i = 0; i < full; i += 3) {
    const n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
    out[o++] = ALPHABET[(n >> 18) & 63];
    out[o++] = ALPHABET[(n >> 12) & 63];
    out[o++] = ALPHABET[(n >> 6) & 63];
    out[o++] = ALPHABET[n & 63];
  }
  switch (data.length % 3) {
    case 1: {
      const n = data[full] << 16;
      out[o++] = ALPHABET[(n >> 18) & 63];
      out[o++] = ALPHABET[(n >> 12) & 63];
      out[o++] = PAD;
      out[o++] = PAD;
      break;
    }
    case 2: {
      const n = (data[full] << 16) | (data[full + 1] << 8);
      out[o++] = ALPHABET[(n >> 18) & 63];
      out[o++] = ALPHABET[(n >> 12) & 63];
      out[o++] = ALPHABET[(n >> 6) & 63];
      out[o++] = PAD;
      break;
    }
  }
  return out.subarray(0, o);
}

// 查表：字母表字符 → 6 位值；非字母表字符 → -1（调用方跳过）。
const LOOKUP = (() => {
  const t = new Int8Array(256).fill(-1);
  for (let i = 0; i < 64; i++) t[ALPHABET[i]] = i;
  return t;
})();

// customB64 编码（含首尾交换）。
export function encode(data) {
  const enc = b64Core(data instanceof Uint8Array ? data : Buffer.from(data));
  return Buffer.from(swapSegments(enc)).toString("latin1");
}

// customB64 解码：剥 \r \n（只剥这两个）→ 同一交换（对合）→ 跳过非字母表
// 字符（`$` 填充必须留着参与交换，不能提前剥）→ 6 位累积。
export function decode(wire) {
  const bytes = typeof wire === "string" ? Buffer.from(wire, "latin1") : wire;
  const cleaned = bytes.filter ? bytes.filter((b) => b !== 0x0d && b !== 0x0a) : bytes;
  const restored = swapSegments(cleaned);
  let acc = 0;
  let bits = 0;
  const out = [];
  for (let i = 0; i < restored.length; i++) {
    const v = LOOKUP[restored[i]];
    if (v < 0) continue; // '$' 填充（还原后回到原位）与任何杂散字符
    acc = ((acc << 6) | v) >>> 0;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

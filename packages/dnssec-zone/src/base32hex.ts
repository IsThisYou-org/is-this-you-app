const ALPHABET = '0123456789abcdefghijklmnopqrstuv';

export function base32hexEncode(data: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of data) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(value >>> bits) & 31];
    }
  }
  if (bits > 0) {
    out += ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

export function base32hexDecode(text: string): Uint8Array {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of text.trim().toLowerCase()) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) {
      throw new Error(`Bad base32hex: ${text}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 255);
    }
  }
  return Uint8Array.from(out);
}

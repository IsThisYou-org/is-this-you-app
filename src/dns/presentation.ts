import { decodeHex, encodeBase64, encodeHex, utf8Encode } from '../bytes';
import { Writer } from './writer';

export function presentCharString(bytes: Uint8Array): string {
  let out = '"';
  for (const b of bytes) {
    if (b === 0x22) {
      out += '\\"';
    } else if (b === 0x5c) {
      out += '\\\\';
    } else if (b >= 0x20 && b <= 0x7e) {
      out += String.fromCharCode(b);
    } else {
      out += '\\' + b.toString(8).padStart(3, '0');
    }
  }
  return out + '"';
}

export function presentTxt(text: string): string {
  const bytes = utf8Encode(text);
  if (bytes.length === 0) {
    return '""';
  }
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += 255) {
    parts.push(presentCharString(bytes.subarray(i, Math.min(i + 255, bytes.length))));
  }
  return parts.join(' ');
}

export function txtWire(text: string): Uint8Array {
  const bytes = utf8Encode(text);
  const w = new Writer();
  if (bytes.length === 0) {
    w.u8(0);
    return w.concat();
  }
  for (let i = 0; i < bytes.length; i += 255) {
    const slice = bytes.subarray(i, Math.min(i + 255, bytes.length));
    w.u8(slice.length);
    w.bytes(slice);
  }
  return w.concat();
}

export function parseQuotedStrings(input: string): Uint8Array[] {
  const out: Uint8Array[] = [];
  let i = 0;
  while (i < input.length) {
    while (input[i] === ' ' || input[i] === '\t') {
      i++;
    }
    if (i >= input.length) {
      break;
    }
    if (input[i] !== '"') {
      throw new Error(`Expected a quoted string in: ${input}`);
    }
    i++;
    const bytes: number[] = [];
    while (i < input.length && input[i] !== '"') {
      if (input[i] === '\\') {
        i++;
        if (i >= input.length) {
          throw new Error('Truncated escape');
        }
        if (input[i] >= '0' && input[i] <= '7') {
          const oct = input.slice(i, i + 3);
          if (!/^[0-7]{3}$/.test(oct)) {
            throw new Error(`Bad octal escape in: ${input}`);
          }
          bytes.push(parseInt(oct, 8));
          i += 3;
        } else {
          bytes.push(input.charCodeAt(i));
          i++;
        }
      } else {
        const c = input.charCodeAt(i);
        if (c > 127) {
          throw new Error('TXT presentation must be ASCII');
        }
        bytes.push(c);
        i++;
      }
    }
    if (input[i] !== '"') {
      throw new Error(`Unterminated string in: ${input}`);
    }
    i++;
    out.push(Uint8Array.from(bytes));
  }
  return out;
}

export function txtWireFromPresentation(presentation: string): Uint8Array {
  const chunks = parseQuotedStrings(presentation);
  const w = new Writer();
  for (const chunk of chunks) {
    if (chunk.length > 255) {
      throw new Error('TXT character-string longer than 255');
    }
    w.u8(chunk.length);
    w.bytes(chunk);
  }
  return w.concat();
}

export function formatDnsTime(unixSeconds: number): string {
  const d = new Date(unixSeconds * 1000);
  const p = (n: number) => n.toString().padStart(2, '0');
  return (
    `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}` +
    `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`
  );
}

export function parseDnsTime(value: string): number {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/.exec(value);
  if (!m) {
    throw new Error(`Bad DNS time ${value}`);
  }
  return Math.floor(
    Date.UTC(
      Number(m[1]),
      Number(m[2]) - 1,
      Number(m[3]),
      Number(m[4]),
      Number(m[5]),
      Number(m[6]),
    ) / 1000,
  );
}

export function presentSalt(salt: Uint8Array): string {
  return salt.length === 0 ? '-' : encodeHex(salt);
}

export function parseSalt(token: string): Uint8Array {
  if (token === '-') {
    return new Uint8Array();
  }
  return decodeHex(token);
}

export { encodeBase64 };

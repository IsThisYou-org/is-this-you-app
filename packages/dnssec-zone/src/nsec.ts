import { compareBytes, concatBytes, encodeHex } from './bytes';
import { sha1 } from './crypto';
import { base32hexDecode, base32hexEncode } from './base32hex';
import { encodeName, normalizeDnsName, presentName } from './name';
import { CODE_TYPE } from './types';
import { Writer } from './writer';
import { parseSalt, presentSalt } from './presentation';

export function encodeTypeBitmap(types: number[]): Uint8Array {
  const byWindow = new Map<number, Set<number>>();
  for (const t of types) {
    const win = t >> 8;
    const set = byWindow.get(win) ?? new Set<number>();
    set.add(t & 0xff);
    byWindow.set(win, set);
  }
  const w = new Writer();
  for (const win of [...byWindow.keys()].sort((a, b) => a - b)) {
    const set = byWindow.get(win)!;
    let max = 0;
    for (const bit of set) {
      if (bit > max) {
        max = bit;
      }
    }
    const len = Math.floor(max / 8) + 1;
    const bitmap = new Uint8Array(len);
    for (const bit of set) {
      bitmap[bit >> 3] |= 1 << (7 - (bit & 7));
    }
    w.u8(win);
    w.u8(len);
    w.bytes(bitmap);
  }
  return w.concat();
}

export function typeNames(types: number[]): string {
  return [...types]
    .sort((a, b) => a - b)
    .map(code => CODE_TYPE[code] ?? `TYPE${code}`)
    .join(' ');
}

export function nsec3Hash(
  name: string,
  iterations: number,
  salt: Uint8Array,
): Uint8Array {
  let digest = sha1(concatBytes(encodeName(name), salt));
  for (let i = 0; i < iterations; i++) {
    digest = sha1(concatBytes(digest, salt));
  }
  return digest;
}

export function nsec3Wire(input: {
  hashAlg: number;
  flags: number;
  iterations: number;
  salt: Uint8Array;
  next: Uint8Array;
  types: number[];
}): Uint8Array {
  const w = new Writer();
  w.u8(input.hashAlg);
  w.u8(input.flags);
  w.u16(input.iterations);
  w.u8(input.salt.length);
  w.bytes(input.salt);
  w.u8(input.next.length);
  w.bytes(input.next);
  w.bytes(encodeTypeBitmap(input.types));
  return w.concat();
}

export function nsec3ParamWire(input: {
  hashAlg: number;
  flags: number;
  iterations: number;
  salt: Uint8Array;
}): Uint8Array {
  const w = new Writer();
  w.u8(input.hashAlg);
  w.u8(input.flags);
  w.u16(input.iterations);
  w.u8(input.salt.length);
  w.bytes(input.salt);
  return w.concat();
}

export function presentNsec3(input: {
  hashAlg: number;
  flags: number;
  iterations: number;
  salt: Uint8Array;
  next: Uint8Array;
  types: number[];
}): string {
  const types = typeNames(input.types);
  return `${input.hashAlg} ${input.flags} ${input.iterations} ${presentSalt(input.salt)} ${base32hexEncode(input.next)}${types ? ` ${types}` : ''}`;
}

export function presentNsec3Param(input: {
  hashAlg: number;
  flags: number;
  iterations: number;
  salt: Uint8Array;
}): string {
  return `${input.hashAlg} ${input.flags} ${input.iterations} ${presentSalt(input.salt)}`;
}

export function parseNsec3(presentation: string): {
  hashAlg: number;
  flags: number;
  iterations: number;
  salt: Uint8Array;
  next: Uint8Array;
  types: number[];
} {
  const parts = presentation.trim().split(/\s+/);
  if (parts.length < 5) {
    throw new Error(`Bad NSEC3: ${presentation}`);
  }
  return {
    hashAlg: Number(parts[0]),
    flags: Number(parts[1]),
    iterations: Number(parts[2]),
    salt: parseSalt(parts[3]),
    next: base32hexDecode(parts[4]),
    types: parts.slice(5).map(token => {
      const code = Object.entries(CODE_TYPE).find(([, name]) => name === token);
      if (!code) {
        throw new Error(`Unknown type ${token}`);
      }
      return Number(code[0]);
    }),
  };
}

export function parseNsec3Param(presentation: string): {
  hashAlg: number;
  flags: number;
  iterations: number;
  salt: Uint8Array;
} {
  const parts = presentation.trim().split(/\s+/);
  if (parts.length !== 4) {
    throw new Error(`Bad NSEC3PARAM: ${presentation}`);
  }
  return {
    hashAlg: Number(parts[0]),
    flags: Number(parts[1]),
    iterations: Number(parts[2]),
    salt: parseSalt(parts[3]),
  };
}

export function nsecWire(nextName: string, types: number[]): Uint8Array {
  return concatBytes(encodeName(nextName), encodeTypeBitmap(types));
}

export function presentNsec(nextName: string, types: number[]): string {
  const names = typeNames(types);
  return `${presentName(nextName)}${names ? ` ${names}` : ''}`;
}

export function parseNsec(presentation: string): {
  nextName: string;
  types: number[];
} {
  const parts = presentation.trim().split(/\s+/);
  if (parts.length < 1) {
    throw new Error('Bad NSEC');
  }
  return {
    nextName: parts[0],
    types: parts.slice(1).map(token => {
      const code = Object.entries(CODE_TYPE).find(([, name]) => name === token);
      if (!code) {
        throw new Error(`Unknown type ${token}`);
      }
      return Number(code[0]);
    }),
  };
}

export function nsec3Owner(hash: Uint8Array, apex: string): string {
  return `${base32hexEncode(hash)}.${normalizeDnsName(apex)}`;
}

export function saltEquals(a: Uint8Array, b: Uint8Array): boolean {
  return compareBytes(a, b) === 0 && a.length === b.length;
}

export function describeSalt(salt: Uint8Array): string {
  return salt.length === 0 ? 'empty' : encodeHex(salt);
}

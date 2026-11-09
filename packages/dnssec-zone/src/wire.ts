import { compareBytes, concatBytes, decodeBase64, encodeHex, utf8Encode } from './bytes';
import { verifyP256, verifyRsaSha256, parseRsaDnskey } from './crypto';
import { encodeName } from './name';
import { canonicalRr } from './rrsig';
import { dsWire } from './ds';
import { nsec3Wire, nsecWire, parseNsec, parseNsec3, parseNsec3Param, nsec3ParamWire } from './nsec';
import { txtWireFromPresentation } from './presentation';
import { TYPE_CODE } from './types';
import { Writer } from './writer';

export interface WireRr {
  name: string;
  type: number;
  ttl: number;
  rdata: Uint8Array;
  text?: string;
}

export interface WireName {
  wire: Uint8Array;
  text: string;
  end: number;
}

/** Decode an uncompressed domain name from DNS wire. */
export function decodeWireName(buf: Uint8Array, offset: number): WireName {
  const labels: Uint8Array[] = [];
  let i = offset;
  while (i < buf.length) {
    const len = buf[i];
    if (len === 0) {
      i++;
      break;
    }
    if ((len & 0xc0) !== 0) {
      throw new Error('Compressed name in RDATA');
    }
    i++;
    if (i + len > buf.length) {
      throw new Error('Truncated DNS name');
    }
    labels.push(buf.subarray(i, i + len));
    i += len;
  }
  const w = new Writer();
  const texts: string[] = [];
  for (const label of labels) {
    const lower = new Uint8Array(label.length);
    let text = '';
    for (let k = 0; k < label.length; k++) {
      const b = label[k];
      const lo = b >= 0x41 && b <= 0x5a ? b + 32 : b;
      lower[k] = lo;
      if (lo >= 0x21 && lo <= 0x7e && lo !== 0x2e && lo !== 0x5c) {
        text += String.fromCharCode(lo);
      } else {
        text += '\\' + lo.toString(8).padStart(3, '0');
      }
    }
    w.u8(lower.length);
    w.bytes(lower);
    texts.push(text);
  }
  w.u8(0);
  return { wire: w.concat(), text: texts.length ? texts.join('.') : '.', end: i };
}

/** Presentation name, including `\DDD` escapes, to canonical wire. */
export function presentationNameToWire(input: string): Uint8Array {
  const raw = input.trim();
  if (raw === '' || raw === '.') {
    return Uint8Array.of(0);
  }
  let name = raw.endsWith('.') ? raw.slice(0, -1) : raw;
  const w = new Writer();
  let i = 0;
  while (i < name.length) {
    const label: number[] = [];
    while (i < name.length && name[i] !== '.') {
      if (name[i] === '\\') {
        i++;
        if (i >= name.length) {
          throw new Error(`Bad escape in ${input}`);
        }
        if (name[i] >= '0' && name[i] <= '9') {
          const oct = name.slice(i, i + 3);
          if (!/^[0-7]{3}$/.test(oct)) {
            throw new Error(`Bad octal in ${input}`);
          }
          label.push(parseInt(oct, 8));
          i += 3;
        } else {
          label.push(name.charCodeAt(i) & 0xff);
          i++;
        }
      } else {
        let c = name.charCodeAt(i);
        if (c >= 0x41 && c <= 0x5a) {
          c += 32;
        }
        label.push(c);
        i++;
      }
    }
    if (label.length < 1 || label.length > 63) {
      throw new Error(`Bad label in ${input}`);
    }
    w.u8(label.length);
    w.bytes(Uint8Array.from(label));
    if (name[i] === '.') {
      i++;
    }
  }
  w.u8(0);
  return w.concat();
}

export function ownerWire(name: string): Uint8Array {
  try {
    return encodeName(name);
  } catch {
    return presentationNameToWire(name);
  }
}

export function sameWireName(a: string, b: string): boolean {
  return compareBytes(ownerWire(a), ownerWire(b)) === 0;
}

/** Right-to-left canonical order, as used by NSEC. */
export function compareWireNames(a: Uint8Array, b: Uint8Array): number {
  const la = labelsOf(a);
  const lb = labelsOf(b);
  const n = Math.max(la.length, lb.length);
  for (let i = 0; i < n; i++) {
    if (i >= la.length) {
      return -1;
    }
    if (i >= lb.length) {
      return 1;
    }
    const c = compareBytes(la[la.length - 1 - i], lb[lb.length - 1 - i]);
    if (c !== 0) {
      return c;
    }
  }
  return 0;
}

function labelsOf(wire: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  let i = 0;
  while (i < wire.length && wire[i] !== 0) {
    const len = wire[i];
    out.push(wire.subarray(i + 1, i + 1 + len));
    i += 1 + len;
  }
  return out;
}

export function decodeTypeBitmap(
  buf: Uint8Array,
  offset: number,
): { types: number[]; end: number } {
  const types: number[] = [];
  let i = offset;
  while (i + 1 < buf.length) {
    const win = buf[i];
    const len = buf[i + 1];
    i += 2;
    if (i + len > buf.length) {
      throw new Error('Truncated type bitmap');
    }
    for (let b = 0; b < len; b++) {
      const byte = buf[i + b];
      for (let bit = 0; bit < 8; bit++) {
        if (byte & (1 << (7 - bit))) {
          types.push((win << 8) | (b * 8 + bit));
        }
      }
    }
    i += len;
  }
  return { types, end: i };
}

export interface ParsedRrsig {
  typeCovered: number;
  algorithm: number;
  labels: number;
  originalTtl: number;
  expiration: number;
  inception: number;
  keyTag: number;
  signer: string;
  signature: Uint8Array;
  prefix: Uint8Array;
}

export function parseRrsigRdata(rdata: Uint8Array): ParsedRrsig {
  if (rdata.length < 20) {
    throw new Error('RRSIG RDATA is too short');
  }
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const name = decodeWireName(rdata, 18);
  return {
    typeCovered: view.getUint16(0),
    algorithm: rdata[2],
    labels: rdata[3],
    originalTtl: view.getUint32(4),
    expiration: view.getUint32(8),
    inception: view.getUint32(12),
    keyTag: view.getUint16(16),
    signer: name.text,
    signature: rdata.subarray(name.end),
    prefix: rdata.subarray(0, name.end),
  };
}

export function rrsetPreimage(
  owner: string,
  type: number,
  originalTtl: number,
  rdatas: Uint8Array[],
  prefix: Uint8Array,
): Uint8Array {
  const ownerW = ownerWire(owner);
  const sorted = [...rdatas].sort(compareBytes);
  return concatBytes(
    prefix,
    ...sorted.map(rdata => canonicalRr(ownerW, type, originalTtl, rdata)),
  );
}

export function verifySignature(
  message: Uint8Array,
  signature: Uint8Array,
  algorithm: number,
  dnskeyRdata: Uint8Array,
): boolean {
  if (dnskeyRdata.length < 5 || dnskeyRdata[3] !== algorithm) {
    return false;
  }
  const pubkey = dnskeyRdata.subarray(4);
  if (algorithm === 13) {
    return pubkey.length === 64 && verifyP256(message, signature, pubkey);
  }
  if (algorithm === 8) {
    try {
      const rsa = parseRsaDnskey(pubkey);
      return verifyRsaSha256(message, signature, rsa.e, rsa.n);
    } catch {
      return false;
    }
  }
  return false;
}

export function presentationToRdata(type: number, data: string): Uint8Array {
  const text = data.trim();
  if (type === TYPE_CODE.TXT || type === TYPE_CODE.WALLET) {
    return txtWireFromPresentation(text);
  }
  if (type === TYPE_CODE.NS) {
    return presentationNameToWire(text);
  }
  if (type === TYPE_CODE.DS) {
    const p = text.split(/\s+/);
    return dsWire({
      keyTag: Number(p[0]),
      algorithm: Number(p[1]),
      digestType: Number(p[2]),
      digest: hexToBytes(p.slice(3).join('')),
    });
  }
  if (type === TYPE_CODE.DNSKEY) {
    const p = text.split(/\s+/);
    const w = new Writer();
    w.u16(Number(p[0]));
    w.u8(Number(p[1]));
    w.u8(Number(p[2]));
    w.bytes(decodeBase64(p.slice(3).join('')));
    return w.concat();
  }
  if (type === TYPE_CODE.RRSIG) {
    const p = text.split(/\s+/);
    if (p.length < 9) {
      throw new Error('Bad RRSIG presentation');
    }
    const signer = p[7];
    const signature = decodeBase64(p.slice(8).join(''));
    const { rrsigPrefix } = requireRrsig();
    const { parseDnsTime } = requirePresentation();
    const { typeCode } = requireTypes();
    const prefix = rrsigPrefix({
      typeCovered: typeCode(p[0].toUpperCase()),
      algorithm: Number(p[1]),
      labels: Number(p[2]),
      originalTtl: Number(p[3]),
      expiration: parseDnsTime(p[4]),
      inception: parseDnsTime(p[5]),
      keyTag: Number(p[6]),
      signer: signer === '.' ? '.' : signer,
    });
    if (signer === '.') {
      return concatBytes(prefixRoot(p, signature), signature);
    }
    return concatBytes(prefix, signature);
  }
  if (type === TYPE_CODE.SOA) {
    const p = text.split(/\s+/);
    const w = new Writer();
    w.bytes(presentationNameToWire(p[0]));
    w.bytes(presentationNameToWire(p[1]));
    for (let i = 2; i < 7; i++) {
      w.u32(Number(p[i]));
    }
    return w.concat();
  }
  if (type === TYPE_CODE.NSEC3) {
    const parsed = parseNsec3(text);
    return nsec3Wire(parsed);
  }
  if (type === TYPE_CODE.NSEC3PARAM) {
    const parsed = parseNsec3Param(text);
    return nsec3ParamWire(parsed);
  }
  if (type === TYPE_CODE.NSEC) {
    const parsed = parseNsec(text);
    return nsecWire(parsed.nextName, parsed.types);
  }
  if (type === TYPE_CODE.URI) {
    const match = /^(\d+)\s+(\d+)\s+([\s\S]+)$/.exec(text);
    if (!match) {
      throw new Error('Bad URI presentation');
    }
    const target = unquote(match[3]);
    const bytes = utf8Encode(target);
    const w = new Writer();
    w.u16(Number(match[1]));
    w.u16(Number(match[2]));
    w.bytes(bytes);
    return w.concat();
  }
  throw new Error(`No presentation parser for type ${type} (${encodeHex(new Uint8Array())})`);
}

function prefixRoot(
  p: string[],
  _signature: Uint8Array,
): Uint8Array {
  const { typeCode } = requireTypes();
  const { parseDnsTime } = requirePresentation();
  const w = new Writer();
  w.u16(typeCode(p[0].toUpperCase()));
  w.u8(Number(p[1]));
  w.u8(Number(p[2]));
  w.u32(Number(p[3]));
  w.u32(parseDnsTime(p[4]));
  w.u32(parseDnsTime(p[5]));
  w.u16(Number(p[6]));
  w.u8(0);
  return w.concat();
}

function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  return trimmed;
}

function hexToBytes(hex: string): Uint8Array {
  const s = hex.trim();
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function requireRrsig(): typeof import('./rrsig') {
  return require('./rrsig');
}
function requirePresentation(): typeof import('./presentation') {
  return require('./presentation');
}
function requireTypes(): typeof import('./types') {
  return require('./types');
}

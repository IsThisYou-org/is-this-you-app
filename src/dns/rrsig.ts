import {
  compareBytes,
  concatBytes,
  decodeBase64,
  encodeBase64,
} from '../bytes';
import { encodeName, labelCount, presentName } from './name';
import { CODE_TYPE, typeCode } from './types';
import { Writer } from './writer';
import { formatDnsTime, parseDnsTime } from './presentation';

export function keyTag(rdata: Uint8Array): number {
  let ac = 0;
  for (let i = 0; i < rdata.length; i++) {
    const v = rdata[i];
    ac = (ac + ((i & 1) === 1 ? v : v << 8)) >>> 0;
  }
  ac = (ac + ((ac >>> 16) & 0xffff)) >>> 0;
  return ac & 0xffff;
}

export function dnskeyRdata(flags: number, publicRaw: Uint8Array): Uint8Array {
  if (publicRaw.length !== 64) {
    throw new Error('DNSKEY public key must be 64 bytes');
  }
  const w = new Writer();
  w.u16(flags);
  w.u8(3);
  w.u8(13);
  w.bytes(publicRaw);
  return w.concat();
}

export function canonicalRr(
  owner: Uint8Array,
  type: number,
  ttl: number,
  rdata: Uint8Array,
): Uint8Array {
  const w = new Writer();
  w.bytes(owner);
  w.u16(type);
  w.u16(1);
  w.u32(ttl);
  w.u16(rdata.length);
  w.bytes(rdata);
  return w.concat();
}

export interface RrsigFields {
  typeCovered: number;
  algorithm: number;
  labels: number;
  originalTtl: number;
  expiration: number;
  inception: number;
  keyTag: number;
  signer: string;
}

export function rrsigPrefix(fields: RrsigFields): Uint8Array {
  const w = new Writer();
  w.u16(fields.typeCovered);
  w.u8(fields.algorithm);
  w.u8(fields.labels);
  w.u32(fields.originalTtl);
  w.u32(fields.expiration);
  w.u32(fields.inception);
  w.u16(fields.keyTag);
  w.bytes(encodeName(fields.signer));
  return w.concat();
}

export function rrsigPreimage(
  owner: string,
  type: number,
  ttl: number,
  rdatas: Uint8Array[],
  prefix: Uint8Array,
): Uint8Array {
  const ownerWire = encodeName(owner);
  const sorted = [...rdatas].sort(compareBytes);
  const parts = [prefix];
  for (const rdata of sorted) {
    parts.push(canonicalRr(ownerWire, type, ttl, rdata));
  }
  return concatBytes(...parts);
}

export function presentRrsig(fields: RrsigFields, signature: Uint8Array): string {
  const typeName = CODE_TYPE[fields.typeCovered];
  if (!typeName) {
    throw new Error(`No mnemonic for type ${fields.typeCovered}`);
  }
  return [
    typeName,
    String(fields.algorithm),
    String(fields.labels),
    String(fields.originalTtl),
    formatDnsTime(fields.expiration),
    formatDnsTime(fields.inception),
    String(fields.keyTag),
    presentName(fields.signer),
    encodeBase64(signature),
  ].join(' ');
}

export function parseRrsig(presentation: string): RrsigFields & {
  signature: Uint8Array;
} {
  const parts = presentation.trim().split(/\s+/);
  if (parts.length !== 9) {
    throw new Error(`Bad RRSIG presentation: ${presentation}`);
  }
  return {
    typeCovered: typeCode(parts[0]),
    algorithm: Number(parts[1]),
    labels: Number(parts[2]),
    originalTtl: Number(parts[3]),
    expiration: parseDnsTime(parts[4]),
    inception: parseDnsTime(parts[5]),
    keyTag: Number(parts[6]),
    signer: parts[7],
    signature: decodeBase64(parts[8]),
  };
}

export function presentDnskey(flags: number, publicRaw: Uint8Array): string {
  return `${flags} 3 13 ${encodeBase64(publicRaw)}`;
}

export function ownerLabelsOk(owner: string, labels: number): boolean {
  return labelCount(owner) === labels;
}

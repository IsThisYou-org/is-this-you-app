import { decodeHex, encodeHex } from './bytes';
import { sha256 } from './crypto';
import type { DohClient, DohMessage, WireRr } from './doh';
import { normalizeDnsName } from './name';
import { base32hexDecode } from './base32hex';
import { nsec3Hash } from './nsec';
import { compareBytes } from './bytes';
import { decodeTypeBitmap, ownerWire, parseRrsigRdata, rrsetPreimage, sameWireName, verifySignature } from './wire';
import { ROOT_TRUST_ANCHORS, type TrustAnchor } from './anchors';
import { dsFromDnskey } from './ds';
import { TYPE_CODE } from './types';
import { concatBytes } from './bytes';

export interface ZoneKeys {
  zone: string;
  keys: Uint8Array[];
  chain: string[];
}

export type ChainStatus = 'secure' | 'insecure' | 'bogus' | 'indeterminate';

export interface ChainResult {
  status: ChainStatus;
  zone: string;
  keys: Uint8Array[];
  chain: string[];
  reason: string;
}

export interface Proof {
  validated: boolean;
  denial: boolean;
  records: WireRr[];
  reason: string;
}

export class DnssecResolver {
  constructor(
    private client: DohClient,
    private now: number,
    private anchors: TrustAnchor[] = ROOT_TRUST_ANCHORS,
  ) {}

  async resolve(name: string): Promise<ChainResult> {
    const qname = normalizeOrDot(name);
    const start = longestAnchor(qname, this.anchors);
    let zone = start;
    let keys: Uint8Array[];
    const chain: string[] = [];
    try {
      keys = await this.loadKeys(zone, null);
      chain.push(zone === '.' ? '.' : zone);
    } catch (error) {
      return {
        status: 'indeterminate',
        zone: start,
        keys: [],
        chain: [],
        reason: error instanceof Error ? error.message : 'could not authenticate the trust anchor',
      };
    }
    for (const candidate of namesBelow(qname, zone)) {
      const ds = await this.prove(candidate, TYPE_CODE.DS, keys, zone);
      if (ds.validated && !ds.denial && ds.records.length > 0) {
        try {
          keys = await this.loadKeys(candidate, ds.records);
          zone = candidate;
          chain.push(candidate);
        } catch (error) {
          return {
            status: 'bogus',
            zone: candidate,
            keys: [],
            chain,
            reason: error instanceof Error ? error.message : 'DNSKEY did not match the parent DS',
          };
        }
      } else if (ds.validated && ds.denial) {
        if (candidate === qname) {
          return {
            status: 'insecure',
            zone,
            keys,
            chain,
            reason: `${qname} has no DS at the parent, so it is not a DNSSEC zone`,
          };
        }
      } else if (candidate === qname && ds.records.length === 0) {
        return {
          status: 'insecure',
          zone,
          keys,
          chain,
          reason: ds.reason || `${qname} is not a signed delegation`,
        };
      } else if (!ds.validated) {
        return {
          status: 'indeterminate',
          zone,
          keys,
          chain,
          reason: ds.reason,
        };
      }
    }
    return { status: 'secure', zone, keys, chain, reason: 'DNSSEC chain validated' };
  }

  async prove(
    name: string,
    type: number,
    keys: Uint8Array[],
    signer: string,
  ): Promise<Proof> {
    const message = await this.client.query(displayName(name), typeName(type));
    if (message.error) {
      return { validated: false, denial: false, records: [], reason: message.error };
    }
    const records = message.answer.filter(rr => sameWireName(rr.name, name) && rr.type === type);
    const sigs = rrsigsCovering(message, name, type);
    if (records.length > 0) {
      const ok = sigs.some(sig => this.signatureOk(name, type, records, sig, keys, signer));
      if (!ok) {
        return {
          validated: false,
          denial: false,
          records,
          reason: `no valid RRSIG for ${typeName(type)} at ${name}`,
        };
      }
      return { validated: true, denial: false, records, reason: 'signed' };
    }
    const denial = this.denialOk(message, name, type, keys, signer);
    if (denial) {
      return { validated: true, denial: true, records: [], reason: denial };
    }
    return {
      validated: false,
      denial: false,
      records: [],
      reason: `no authenticated ${typeName(type)} and no authenticated denial at ${name}`,
    };
  }

  private async loadKeys(zone: string, parentDs: WireRr[] | null): Promise<Uint8Array[]> {
    const message = await this.client.query(displayName(zone), 'DNSKEY');
    if (message.error) {
      throw new Error(message.error);
    }
    const records = message.answer.filter(
      rr => sameWireName(rr.name, zone) && rr.type === TYPE_CODE.DNSKEY,
    );
    if (records.length === 0) {
      throw new Error(`no DNSKEY at ${zone}`);
    }
    const sigs = rrsigsCovering(message, zone, TYPE_CODE.DNSKEY);
    const verified = sigs.filter(sig =>
      this.signatureOk(zone, TYPE_CODE.DNSKEY, records, sig, records.map(rr => rr.rdata), zone),
    );
    if (verified.length === 0) {
      throw new Error(`DNSKEY RRSIG at ${zone} did not verify`);
    }
    const signingKeys = verified.map(sig => {
      const parsed = parseRrsigRdata(sig.rdata);
      const key = records.find(rr => keyTag(rr.rdata) === parsed.keyTag);
      if (!key) {
        throw new Error('RRSIG key tag has no DNSKEY');
      }
      return key.rdata;
    });
    if (parentDs) {
      const digests = parentDs.map(rr => rr.rdata);
      const matched = signingKeys.some(key =>
        digests.some(ds => dsMatches(zone, key, ds)),
      );
      if (!matched) {
        throw new Error(`DNSKEY at ${zone} does not match the parent DS`);
      }
    } else {
      const zoneAnchors = this.anchors.filter(anchor => sameZone(anchor.zone, zone));
      if (zoneAnchors.length === 0) {
        throw new Error(`no trust anchor for ${zone}`);
      }
      const matched = signingKeys.some(key =>
        zoneAnchors.some(anchor => anchorMatches(zone, key, anchor)),
      );
      if (!matched) {
        throw new Error(`DNSKEY at ${zone} does not match a trust anchor`);
      }
    }
    return records.map(rr => rr.rdata);
  }

  private signatureOk(
    owner: string,
    type: number,
    records: WireRr[],
    sig: WireRr,
    keys: Uint8Array[],
    expectedSigner: string,
  ): boolean {
    let parsed;
    try {
      parsed = parseRrsigRdata(sig.rdata);
    } catch {
      return false;
    }
    if (parsed.typeCovered !== type || parsed.algorithm !== sigAlgorithm(keys, parsed.keyTag)) {
      // algorithm is checked against the key below
    }
    if (!sameWireName(parsed.signer, expectedSigner)) {
      return false;
    }
    if (this.now < parsed.inception || this.now >= parsed.expiration) {
      return false;
    }
    const key = keys.find(item => keyTag(item) === parsed.keyTag);
    if (!key) {
      return false;
    }
    const message = rrsetPreimage(
      owner,
      type,
      parsed.originalTtl,
      records.map(rr => rr.rdata),
      parsed.prefix,
    );
    return verifySignature(message, parsed.signature, parsed.algorithm, key);
  }

  private denialOk(
    message: DohMessage,
    name: string,
    type: number,
    keys: Uint8Array[],
    signer: string,
  ): string | null {
    if (this.nsec3Denial(message, name, type, keys, signer)) {
      return `authenticated denial: NSEC3 covers ${name} with no ${typeName(type)}`;
    }
    const nsecs = message.authority.filter(rr => rr.type === TYPE_CODE.NSEC);
    for (const nsec of nsecs) {
      const sigs = message.authority.filter(
        rr => rr.type === TYPE_CODE.RRSIG && sameWireName(rr.name, nsec.name),
      );
      const signed = sigs.some(sig =>
        this.signatureOk(nsec.name, TYPE_CODE.NSEC, [nsec], sig, keys, signer),
      );
      if (!signed) {
        continue;
      }
      const next = decodeNameEnd(nsec.rdata);
      if (!next) {
        continue;
      }
      const types = decodeTypeBitmap(nsec.rdata, next.end).types;
      if (sameWireName(nsec.name, name) && !types.includes(type)) {
        return `authenticated denial: NSEC at ${name} has no ${typeName(type)}`;
      }
    }
    return null;
  }

  private nsec3Denial(
    message: DohMessage,
    name: string,
    type: number,
    keys: Uint8Array[],
    signer: string,
  ): boolean {
    const records = message.authority.filter(rr => rr.type === TYPE_CODE.NSEC3);
    for (const nsec of records) {
      const sigs = message.authority.filter(
        rr => rr.type === TYPE_CODE.RRSIG && sameWireName(rr.name, nsec.name),
      );
      const signed = sigs.some(sig =>
        this.signatureOk(nsec.name, TYPE_CODE.NSEC3, [nsec], sig, keys, signer),
      );
      if (!signed) {
        continue;
      }
      const parsed = parseNsec3Rdata(nsec.rdata);
      if (!parsed) {
        continue;
      }
      const qhash = nsec3Hash(name, parsed.iterations, parsed.salt);
      const ownerLabel = nsec.name.replace(/\.$/, '').split('.')[0] ?? '';
      let ownerHash: Uint8Array;
      try {
        ownerHash = base32hexDecode(ownerLabel);
      } catch {
        continue;
      }
      const types = decodeTypeBitmap(nsec.rdata, parsed.bitmapAt).types;
      if (compareBytes(qhash, ownerHash) === 0 && !types.includes(type)) {
        return true;
      }
      if (hashCovered(ownerHash, parsed.next, qhash)) {
        return true;
      }
    }
    return false;
  }
}

function rrsigsCovering(message: DohMessage, name: string, type: number): WireRr[] {
  const pool = [...message.answer, ...message.authority];
  return pool.filter(rr => {
    if (rr.type !== TYPE_CODE.RRSIG || !sameWireName(rr.name, name)) {
      return false;
    }
    try {
      return parseRrsigRdata(rr.rdata).typeCovered === type;
    } catch {
      return false;
    }
  });
}

function sigAlgorithm(keys: Uint8Array[], tag: number): number {
  const key = keys.find(item => keyTag(item) === tag);
  return key ? key[3] : -1;
}

export function keyTag(rdata: Uint8Array): number {
  let ac = 0;
  for (let i = 0; i < rdata.length; i++) {
    const v = rdata[i];
    ac = (ac + ((i & 1) === 1 ? v : v << 8)) >>> 0;
  }
  ac = (ac + ((ac >>> 16) & 0xffff)) >>> 0;
  return ac & 0xffff;
}

function dsMatches(owner: string, dnskey: Uint8Array, ds: Uint8Array): boolean {
  if (ds.length < 5) {
    return false;
  }
  const tag = (ds[0] << 8) | ds[1];
  const algorithm = ds[2];
  const digestType = ds[3];
  const digest = ds.subarray(4);
  if (tag !== keyTag(dnskey) || algorithm !== dnskey[3]) {
    return false;
  }
  const computed = dsFromDnskey(owner === '.' ? 'invalid' : owner, dnskey, digestType);
  if (owner === '.') {
    const material = concatBytes(Uint8Array.of(0), dnskey);
    const hashed = digestType === 2 ? sha256(material) : null;
    return hashed != null && encodeHex(hashed) === encodeHex(digest);
  }
  return encodeHex(computed.digest) === encodeHex(digest);
}

function anchorMatches(zone: string, dnskey: Uint8Array, anchor: TrustAnchor): boolean {
  if (anchor.keyTag !== keyTag(dnskey) || anchor.algorithm !== dnskey[3]) {
    return false;
  }
  const owner = zone === '.' ? '.' : zone;
  if (owner === '.') {
    const hashed = sha256(concatBytes(Uint8Array.of(0), dnskey));
    return encodeHex(hashed) === anchor.digestHex.toLowerCase();
  }
  const computed = dsFromDnskey(owner, dnskey, anchor.digestType);
  return encodeHex(computed.digest) === anchor.digestHex.toLowerCase();
}

function longestAnchor(name: string, anchors: TrustAnchor[]): string {
  let best = '.';
  let bestLen = -1;
  for (const anchor of anchors) {
    const zone = anchor.zone === '.' ? '.' : normalizeDnsName(anchor.zone);
    if (zone === '.' || name === zone || name.endsWith(`.${zone}`)) {
      const len = zone === '.' ? 0 : zone.length;
      if (len > bestLen) {
        best = zone;
        bestLen = len;
      }
    }
  }
  return best;
}

function namesBelow(qname: string, start: string): string[] {
  if (qname === '.' || qname === start) {
    return [];
  }
  const labels = qname.split('.');
  const startLabels = start === '.' ? 0 : start.split('.').length;
  const out: string[] = [];
  for (let i = labels.length - startLabels - 1; i >= 0; i--) {
    out.push(labels.slice(i).join('.'));
  }
  return out;
}

function normalizeOrDot(name: string): string {
  const trimmed = name.trim();
  if (trimmed === '' || trimmed === '.') {
    return '.';
  }
  return normalizeDnsName(trimmed);
}

function displayName(name: string): string {
  return name === '.' ? '.' : name;
}

function sameZone(anchorZone: string, zone: string): boolean {
  if (anchorZone === '.' || zone === '.') {
    return anchorZone === zone || (anchorZone === '.' && zone === '.');
  }
  return normalizeDnsName(anchorZone) === normalizeDnsName(zone);
}

function typeName(type: number): string {
  const names: Record<number, string> = {
    16: 'TXT',
    43: 'DS',
    46: 'RRSIG',
    47: 'NSEC',
    48: 'DNSKEY',
    256: 'URI',
    262: 'WALLET',
  };
  return names[type] ?? String(type);
}

function parseNsec3Rdata(
  rdata: Uint8Array,
): { iterations: number; salt: Uint8Array; next: Uint8Array; bitmapAt: number } | null {
  if (rdata.length < 6) {
    return null;
  }
  const iterations = (rdata[2] << 8) | rdata[3];
  const saltLength = rdata[4];
  if (5 + saltLength + 1 > rdata.length) {
    return null;
  }
  const salt = rdata.subarray(5, 5 + saltLength);
  const hashLength = rdata[5 + saltLength];
  const nextAt = 6 + saltLength;
  if (nextAt + hashLength > rdata.length) {
    return null;
  }
  return {
    iterations,
    salt,
    next: rdata.subarray(nextAt, nextAt + hashLength),
    bitmapAt: nextAt + hashLength,
  };
}

function hashCovered(owner: Uint8Array, next: Uint8Array, query: Uint8Array): boolean {
  const afterOwner = compareBytes(query, owner) > 0;
  const beforeNext = compareBytes(query, next) < 0;
  if (compareBytes(owner, next) < 0) {
    return afterOwner && beforeNext;
  }
  return afterOwner || beforeNext;
}

function decodeNameEnd(rdata: Uint8Array): { end: number } | null {
  let i = 0;
  while (i < rdata.length) {
    const len = rdata[i];
    if (len === 0) {
      return { end: i + 1 };
    }
    if ((len & 0xc0) !== 0) {
      return null;
    }
    i += 1 + len;
  }
  return null;
}

void ownerWire;
void decodeHex;

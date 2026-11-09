import { encodeHex } from './bytes';
import { sha1, sha256 } from './crypto';
import { encodeName } from './name';
import { concatBytes } from './bytes';
import { keyTag } from './rrsig';
import { Writer } from './writer';

export interface DsParts {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: Uint8Array;
}

export function dsWire(ds: DsParts): Uint8Array {
  const w = new Writer();
  w.u16(ds.keyTag);
  w.u8(ds.algorithm);
  w.u8(ds.digestType);
  w.bytes(ds.digest);
  return w.concat();
}

export function presentDs(ds: DsParts): string {
  return `${ds.keyTag} ${ds.algorithm} ${ds.digestType} ${encodeHex(ds.digest)}`;
}

/** DS digest over the canonical owner name and the DNSKEY RDATA. Digest type 2 is SHA-256. */
export function dsFromDnskey(
  owner: string,
  dnskeyRdata: Uint8Array,
  digestType = 2,
): DsParts {
  const material = concatBytes(encodeName(owner), dnskeyRdata);
  const digest =
    digestType === 2 ? sha256(material) : digestType === 1 ? sha1(material) : null;
  if (!digest) {
    throw new Error(`Unsupported DS digest type ${digestType}`);
  }
  return {
    keyTag: keyTag(dnskeyRdata),
    algorithm: dnskeyRdata[3],
    digestType,
    digest,
  };
}

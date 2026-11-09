import { parseRrsig, rrsigPreimage } from './rrsig';
import { dnskeyRdata } from './rrsig';
import { TYPE_CODE, type ZoneDocument, typeCode } from './types';
import { presentationToRdata, verifySignature } from './wire';
import { parseNsec3Param } from './nsec';

/** Check a zone this package signed: every RRset has a valid algorithm-13 RRSIG. */
export function verifySignedZone(doc: ZoneDocument, now: number): void {
  if (doc.kind !== 'dnsauth#signedZone') {
    throw new Error('zone kind');
  }
  const dnskeys = doc.rrsets.find(
    rr => rr.type === 'DNSKEY' && rr.name === doc.apex,
  );
  if (!dnskeys) {
    throw new Error('missing DNSKEY');
  }
  const keyRdatas = dnskeys.rrdatas.map(text => presentationToRdata(TYPE_CODE.DNSKEY, text));
  const sep = keyRdatas.filter(rdata => (rdata[0] & 0x01) === 0x01 || rdata[1] === 0x01);
  // Flags are a uint16. SEP is the low bit of the flags field: 257 = 0x0101.
  const sepKeys = keyRdatas.filter(rdata => ((rdata[0] << 8) | rdata[1]) === 257);
  const zskKeys = keyRdatas.filter(rdata => ((rdata[0] << 8) | rdata[1]) === 256);
  if (sepKeys.length !== 1 || zskKeys.length !== 1) {
    throw new Error('expected one KSK and one ZSK');
  }
  void sep;

  for (const rr of doc.rrsets) {
    if (rr.type === 'RRSIG') {
      continue;
    }
    const sigSet = doc.rrsets.find(
      item => item.type === 'RRSIG' && item.name === rr.name,
    );
    if (!sigSet) {
      throw new Error(`missing RRSIG at ${rr.name}`);
    }
    const covering = sigSet.rrdatas
      .map(text => ({ text, parsed: parseRrsig(text) }))
      .filter(item => item.parsed.typeCovered === typeCode(rr.type));
    if (covering.length === 0) {
      throw new Error(`no RRSIG covers ${rr.type} at ${rr.name}`);
    }
    const rdatas = rr.rrdatas.map(text => presentationToRdata(typeCode(rr.type), text));
    let ok = false;
    for (const item of covering) {
      if (item.parsed.algorithm !== 13) {
        throw new Error('RRSIG algorithm is not 13');
      }
      if (item.parsed.expiration - item.parsed.inception > 30 * 24 * 60 * 60) {
        throw new Error('RRSIG lifetime exceeds 30 days');
      }
      if (now < item.parsed.inception || now >= item.parsed.expiration) {
        continue;
      }
      const prefix = presentationToRdata(TYPE_CODE.RRSIG, item.text);
      // prefix includes the signature; rebuild from the parsed fields via rrsigPreimage's caller.
      const message = rrsigPreimage(
        rr.name,
        typeCode(rr.type),
        rr.ttl,
        rdatas,
        prefix.subarray(0, prefix.length - item.parsed.signature.length),
      );
      const key = rr.type === 'DNSKEY' ? sepKeys[0] : zskKeys[0];
      if (item.parsed.keyTag !== keyTagOf(key) && rr.type === 'DNSKEY') {
        throw new Error('DNSKEY RRSIG is not the KSK');
      }
      if (rr.type !== 'DNSKEY' && item.parsed.keyTag === keyTagOf(sepKeys[0])) {
        throw new Error('ZSK RRset was signed by the KSK');
      }
      ok = verifySignature(message, item.parsed.signature, 13, key);
      if (ok) {
        break;
      }
    }
    if (!ok) {
      throw new Error(`bad signature for ${rr.type} ${rr.name}`);
    }
  }

  const param = doc.rrsets.find(rr => rr.type === 'NSEC3PARAM');
  if (param) {
    const parsed = parseNsec3Param(param.rrdatas[0]);
    if (parsed.iterations !== 0 || parsed.salt.length !== 0 || parsed.flags !== 0) {
      throw new Error('NSEC3PARAM is not the RFC 9276 default');
    }
  }
}

function keyTagOf(rdata: Uint8Array): number {
  let ac = 0;
  for (let i = 0; i < rdata.length; i++) {
    const v = rdata[i];
    ac = (ac + ((i & 1) === 1 ? v : v << 8)) >>> 0;
  }
  ac = (ac + ((ac >>> 16) & 0xffff)) >>> 0;
  return ac & 0xffff;
}

void dnskeyRdata;

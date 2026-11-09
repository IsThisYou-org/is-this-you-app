import { compareBytes, decodeHex } from './bytes';
import { sha256, utf8Encode } from './crypto';
import { compareNames, encodeName, emptyNonTerminals, normalizeDnsName, presentName } from './name';
import {
  nsec3Hash,
  nsec3Owner,
  nsec3ParamWire,
  nsec3Wire,
  nsecWire,
  presentNsec,
  presentNsec3,
  presentNsec3Param,
} from './nsec';
import { presentTxt, txtWire } from './presentation';
import {
  dnskeyRdata,
  keyTag,
  parseRrsig,
  presentDnskey,
  presentRrsig,
  rrsigPreimage,
  rrsigPrefix,
} from './rrsig';
import { dsWire, presentDs } from './ds';
import {
  assertUriSet,
  encodeWalletRdata,
  presentWallet,
  type UriRecord,
  type WalletFields,
} from './records';
import { TYPE_CODE, type ZoneDocument } from './types';
import { Writer } from './writer';

export interface SigningKey {
  publicRaw: Uint8Array;
  sign(message: Uint8Array): Promise<Uint8Array>;
  signMany?(messages: Uint8Array[]): Promise<Uint8Array[]>;
}

export interface ZoneMaterial {
  apex: string;
  serial: number;
  now: number;
  mname: string;
  rname: string;
  ns: string[];
  ttl: number;
  soa: {
    refresh: number;
    retry: number;
    expire: number;
    minimum: number;
  };
  txt: { owner: string; text: string }[];
  /** URI records, all published at the apex. Priority 0 weight 0 is the single default. */
  uri: UriRecord[];
  /** WALLET records, all published at the apex. */
  wallet: WalletFields[];
  /** DS records this zone publishes for delegated children. */
  ds?: {
    owner: string;
    keyTag: number;
    algorithm: number;
    digestType: number;
    digest: Uint8Array;
  }[];
  ksk: SigningKey;
  zsk: SigningKey;
  resignDnskey: boolean;
  existingDnskeySignatures?: string[];
  nsecMode: 'nsec3' | 'nsec';
  nsec3: {
    iterations: number;
    salt: Uint8Array;
    optOut: boolean;
  };
  validitySeconds: number;
  inceptionBackdateSeconds: number;
  jitterMaxSeconds: number;
}

export interface SignedZone {
  document: ZoneDocument;
  dnskeySignatureRrdatas: string[];
  dnskeyExpiry: number;
  earliestZskExpiry: number;
}

interface UnsignedRr {
  owner: string;
  type: string;
  typeCode: number;
  ttl: number;
  rdatas: Uint8Array[];
  presentations: string[];
  /** Types that exist at this name before RRSIGs are added. */
  coveredTypes: number[];
}

function jitterSeconds(owner: string, type: string, max: number): number {
  if (max <= 0) {
    return 0;
  }
  const hash = sha256(utf8Encode(`${normalizeDnsName(owner)}|${type}`));
  const n = (hash[0] << 8) | hash[1];
  return n % (max + 1);
}

function soaWire(input: ZoneMaterial): Uint8Array {
  const w = new Writer();
  w.bytes(encodeName(input.mname));
  w.bytes(encodeName(input.rname));
  w.u32(input.serial);
  w.u32(input.soa.refresh);
  w.u32(input.soa.retry);
  w.u32(input.soa.expire);
  w.u32(input.soa.minimum);
  return w.concat();
}

function uriWire(
  priority: number,
  weight: number,
  target: string,
): Uint8Array {
  const text = utf8Encode(target);
  const w = new Writer();
  w.u16(priority);
  w.u16(weight);
  w.bytes(text);
  return w.concat();
}

function sortRr(rr: UnsignedRr): UnsignedRr {
  const zipped = rr.rdatas.map((rdata, i) => ({
    rdata,
    presentation: rr.presentations[i],
  }));
  zipped.sort((a, b) => compareBytes(a.rdata, b.rdata));
  return {
    ...rr,
    rdatas: zipped.map(z => z.rdata),
    presentations: zipped.map(z => z.presentation),
  };
}

function typesAt(rrs: UnsignedRr[], owner: string): number[] {
  const types = new Set<number>();
  for (const rr of rrs) {
    if (rr.owner === owner) {
      types.add(rr.typeCode);
    }
  }
  if (types.size > 0) {
    types.add(TYPE_CODE.RRSIG);
  }
  return [...types];
}

export async function signZone(input: ZoneMaterial): Promise<SignedZone> {
  const apex = normalizeDnsName(input.apex);
  const ttl = input.ttl;
  if (input.ns.length === 0) {
    throw new Error('The zone needs at least one NS name');
  }
  const nsSorted = [...input.ns].sort((a, b) =>
    compareBytes(encodeName(a), encodeName(b)),
  );

  const kskRdata = dnskeyRdata(257, input.ksk.publicRaw);
  const zskRdata = dnskeyRdata(256, input.zsk.publicRaw);
  const kskTag = keyTag(kskRdata);
  const zskTag = keyTag(zskRdata);

  const rrs: UnsignedRr[] = [
    sortRr({
      owner: apex,
      type: 'SOA',
      typeCode: TYPE_CODE.SOA,
      ttl,
      rdatas: [soaWire(input)],
      presentations: [
        `${presentName(input.mname)} ${presentName(input.rname)} ${input.serial} ${input.soa.refresh} ${input.soa.retry} ${input.soa.expire} ${input.soa.minimum}`,
      ],
      coveredTypes: [],
    }),
    sortRr({
      owner: apex,
      type: 'NS',
      typeCode: TYPE_CODE.NS,
      ttl,
      rdatas: nsSorted.map(name => encodeName(name)),
      presentations: nsSorted.map(name => presentName(name)),
      coveredTypes: [],
    }),
    sortRr({
      owner: apex,
      type: 'DNSKEY',
      typeCode: TYPE_CODE.DNSKEY,
      ttl,
      rdatas: [kskRdata, zskRdata],
      presentations: [
        presentDnskey(257, input.ksk.publicRaw),
        presentDnskey(256, input.zsk.publicRaw),
      ],
      coveredTypes: [],
    }),
  ];

  for (const txt of input.txt) {
    const owner = normalizeDnsName(txt.owner);
    rrs.push({
      owner,
      type: 'TXT',
      typeCode: TYPE_CODE.TXT,
      ttl,
      rdatas: [txtWire(txt.text)],
      presentations: [presentTxt(txt.text)],
      coveredTypes: [],
    });
  }
  assertUriSet(input.uri);
  for (const uri of input.uri) {
    rrs.push({
      owner: apex,
      type: 'URI',
      typeCode: TYPE_CODE.URI,
      ttl,
      rdatas: [uriWire(uri.priority, uri.weight, uri.target)],
      presentations: [`${uri.priority} ${uri.weight} "${uri.target.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`],
      coveredTypes: [],
    });
  }
  for (const wallet of input.wallet) {
    rrs.push({
      owner: apex,
      type: 'WALLET',
      typeCode: TYPE_CODE.WALLET,
      ttl,
      rdatas: [encodeWalletRdata(wallet)],
      presentations: [presentWallet(wallet)],
      coveredTypes: [],
    });
  }
  for (const ds of input.ds ?? []) {
    rrs.push({
      owner: normalizeDnsName(ds.owner),
      type: 'DS',
      typeCode: TYPE_CODE.DS,
      ttl,
      rdatas: [dsWire(ds)],
      presentations: [presentDs(ds)],
      coveredTypes: [],
    });
  }

  const grouped = groupSameType(rrs);

  if (input.nsecMode === 'nsec3') {
    const salt = input.nsec3.salt;
    const iterations = input.nsec3.iterations;
    const flags = input.nsec3.optOut ? 1 : 0;
    grouped.push({
      owner: apex,
      type: 'NSEC3PARAM',
      typeCode: TYPE_CODE.NSEC3PARAM,
      ttl,
      rdatas: [nsec3ParamWire({ hashAlg: 1, flags: 0, iterations, salt })],
      presentations: [
        presentNsec3Param({ hashAlg: 1, flags: 0, iterations, salt }),
      ],
      coveredTypes: [],
    });
    const owners = grouped.map(rr => rr.owner);
    const ents = emptyNonTerminals(owners, apex);
    const hashedNames = [...new Set([...owners, ...ents])];
    const chain = hashedNames
      .map(name => ({
        name,
        hash: nsec3Hash(name, iterations, salt),
        types: ents.includes(name) ? [] : typesAt(grouped, name),
      }))
      .sort((a, b) => compareBytes(a.hash, b.hash));
    for (let i = 0; i < chain.length; i++) {
      const next = chain[(i + 1) % chain.length].hash;
      const item = chain[i];
      const wire = nsec3Wire({
        hashAlg: 1,
        flags,
        iterations,
        salt,
        next,
        types: item.types,
      });
      grouped.push({
        owner: nsec3Owner(item.hash, apex),
        type: 'NSEC3',
        typeCode: TYPE_CODE.NSEC3,
        ttl,
        rdatas: [wire],
        presentations: [
          presentNsec3({
            hashAlg: 1,
            flags,
            iterations,
            salt,
            next,
            types: item.types,
          }),
        ],
        coveredTypes: [],
      });
    }
  } else {
    const owners = [...new Set(grouped.map(rr => rr.owner))].sort(compareNames);
    for (let i = 0; i < owners.length; i++) {
      const next = owners[(i + 1) % owners.length];
      const types = typesAt(grouped, owners[i]).filter(
        code => code !== TYPE_CODE.NSEC,
      );
      types.push(TYPE_CODE.NSEC);
      const wire = nsecWire(next, types);
      grouped.push({
        owner: owners[i],
        type: 'NSEC',
        typeCode: TYPE_CODE.NSEC,
        ttl,
        rdatas: [wire],
        presentations: [presentNsec(next, types)],
        coveredTypes: [],
      });
    }
  }

  const zskRrs = grouped.filter(rr => rr.type !== 'DNSKEY');
  const dnskey = grouped.find(rr => rr.type === 'DNSKEY');
  if (!dnskey) {
    throw new Error('DNSKEY RRset missing');
  }

  const zskExpiries: number[] = [];
  const zskMessages: Uint8Array[] = [];
  const zskFields = zskRrs.map(rr => {
    const times = signatureWindow(rr.owner, rr.type, input);
    zskExpiries.push(times.expiration);
    const prefix = rrsigPrefix({
      typeCovered: rr.typeCode,
      algorithm: 13,
      labels: rr.owner.split('.').length,
      originalTtl: rr.ttl,
      expiration: times.expiration,
      inception: times.inception,
      keyTag: zskTag,
      signer: apex,
    });
    zskMessages.push(
      rrsigPreimage(rr.owner, rr.typeCode, rr.ttl, rr.rdatas, prefix),
    );
    return times;
  });
  const zskSigs = input.zsk.signMany
    ? await input.zsk.signMany(zskMessages)
    : await Promise.all(zskMessages.map(message => input.zsk.sign(message)));
  if (zskSigs.length !== zskRrs.length) {
    throw new Error('ZSK signer returned the wrong number of signatures');
  }

  let dnskeySigs: string[];
  let dnskeyExpiry: number;
  if (input.resignDnskey) {
    const times = signatureWindow(apex, 'DNSKEY', input);
    const prefix = rrsigPrefix({
      typeCovered: TYPE_CODE.DNSKEY,
      algorithm: 13,
      labels: apex.split('.').length,
      originalTtl: ttl,
      expiration: times.expiration,
      inception: times.inception,
      keyTag: kskTag,
      signer: apex,
    });
    const signature = await input.ksk.sign(
      rrsigPreimage(apex, TYPE_CODE.DNSKEY, ttl, dnskey.rdatas, prefix),
    );
    dnskeySigs = [
      presentRrsig(
        {
          typeCovered: TYPE_CODE.DNSKEY,
          algorithm: 13,
          labels: apex.split('.').length,
          originalTtl: ttl,
          expiration: times.expiration,
          inception: times.inception,
          keyTag: kskTag,
          signer: apex,
        },
        signature,
      ),
    ];
    dnskeyExpiry = times.expiration;
  } else {
    const existing = input.existingDnskeySignatures ?? [];
    if (existing.length === 0) {
      throw new Error('KSK_REQUIRED');
    }
    dnskeySigs = existing;
    dnskeyExpiry = Math.min(...existing.map(item => parseRrsig(item).expiration));
  }

  const rrsets: ZoneDocument['rrsets'] = [];
  const signatures = new Map<string, { ttl: number; rrdatas: string[] }>();
  for (const rr of grouped) {
    const name = presentName(rr.owner);
    const sigs =
      rr.type === 'DNSKEY'
        ? dnskeySigs
        : [
            presentRrsig(
              {
                typeCovered: rr.typeCode,
                algorithm: 13,
                labels: rr.owner.split('.').length,
                originalTtl: rr.ttl,
                expiration: zskFields[zskRrs.indexOf(rr)].expiration,
                inception: zskFields[zskRrs.indexOf(rr)].inception,
                keyTag: zskTag,
                signer: apex,
              },
              zskSigs[zskRrs.indexOf(rr)],
            ),
          ];
    rrsets.push({
      kind: 'dns#resourceRecordSet',
      name,
      type: rr.type,
      ttl: rr.ttl,
      rrdatas: rr.presentations,
    });
    const existing = signatures.get(name) ?? { ttl: rr.ttl, rrdatas: [] };
    existing.rrdatas.push(...sigs);
    signatures.set(name, existing);
  }
  for (const [name, sig] of signatures) {
    rrsets.push({
      kind: 'dns#resourceRecordSet',
      name,
      type: 'RRSIG',
      ttl: sig.ttl,
      rrdatas: sig.rrdatas,
    });
  }

  return {
    document: {
      kind: 'dnsauth#signedZone',
      apex: presentName(apex),
      rrsets,
    },
    dnskeySignatureRrdatas: dnskeySigs,
    dnskeyExpiry,
    earliestZskExpiry: Math.min(...zskExpiries),
  };
}

function signatureWindow(
  owner: string,
  type: string,
  input: ZoneMaterial,
): { inception: number; expiration: number } {
  const jitter = jitterSeconds(owner, type, input.jitterMaxSeconds);
  // The hosting service rejects an RRSIG whose expiry minus inception
  // exceeds 30 days. The backdate therefore comes out of that window.
  const inception = input.now - input.inceptionBackdateSeconds;
  const expiration = inception + input.validitySeconds - jitter;
  if (expiration <= inception) {
    throw new Error('RRSIG expiry is not after inception');
  }
  return { inception, expiration };
}

function groupSameType(rrs: UnsignedRr[]): UnsignedRr[] {
  const map = new Map<string, UnsignedRr>();
  for (const rr of rrs) {
    const key = `${rr.owner}|${rr.type}`;
    const existing = map.get(key);
    if (!existing) {
      map.set(key, rr);
      continue;
    }
    existing.rdatas.push(...rr.rdatas);
    existing.presentations.push(...rr.presentations);
  }
  return [...map.values()].map(sortRr);
}


export function saltFromHex(hex: string): Uint8Array {
  if (!hex) {
    return new Uint8Array();
  }
  return decodeHex(hex);
}

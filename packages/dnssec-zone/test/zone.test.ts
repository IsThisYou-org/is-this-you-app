import { SoftwareKeystore, publicRaw } from '../../keystore/src/index';
import { dsFromDnskey } from '../src/ds';
import { lookupDomain, lookupWallet } from '../src/lookup';
import { signZone, type SigningKey } from '../src/sign';
import { verifySignedZone } from '../src/selfCheck';
import type { DohClient, DohMessage } from '../src/doh';
import type { TrustAnchor } from '../src/anchors';
import { DnssecResolver } from '../src/validate';
import { TYPE_CODE, type ZoneDocument, typeCode } from '../src/types';
import { presentationToRdata, type WireRr } from '../src/wire';
import { parseRrsig } from '../src/rrsig';

const NOW = 1_794_000_000;

async function keys() {
  const store = new SoftwareKeystore();
  const ksk = await store.generateKey({ alias: 'ksk', purpose: 'ksk', requireBiometric: true });
  const zsk = await store.generateKey({ alias: 'zsk', purpose: 'zsk', requireBiometric: false });
  const toKey = (alias: string, record: typeof ksk): SigningKey => ({
    publicRaw: publicRaw(record),
    sign: message => store.sign(alias, message),
    signMany: messages => store.signMany(alias, messages),
  });
  return { store, ksk: toKey('ksk', ksk), zsk: toKey('zsk', zsk), kskRecord: ksk };
}

function material(over: Partial<Parameters<typeof signZone>[0]> = {}) {
  return {
    apex: 'example.test',
    serial: NOW,
    now: NOW,
    mname: 'ns1.example.net',
    rname: 'hostmaster.example.test',
    ns: ['ns1.example.net', 'ns2.example.net'],
    ttl: 300,
    soa: { refresh: 3600, retry: 600, expire: 864000, minimum: 300 },
    txt: [],
    uri: [
      { priority: 0, weight: 0, target: 'https://home.example' },
      { priority: 2, weight: 1, target: 'https://game.example' },
      { priority: 1, weight: 1, target: 'https://social.example' },
    ],
    wallet: [
      { type: 'btc', identifier: 'bc1qexample' },
      { type: 'paypal', identifier: 'ABCD1234EFGH5', description: 'shop', sort: 1 },
    ],
    nsecMode: 'nsec3' as const,
    nsec3: { iterations: 0, salt: new Uint8Array(), optOut: false },
    validitySeconds: 30 * 24 * 60 * 60,
    inceptionBackdateSeconds: 3600,
    jitterMaxSeconds: 0,
    resignDnskey: true,
    ...over,
  };
}

test('signed zone validates, uses NSEC3 defaults, and keeps RRSIG lifetime within 30 days', async () => {
  const made = await keys();
  const before = made.store.biometricPromptCount();
  const signed = await signZone({ ...material(), ksk: made.ksk, zsk: made.zsk });
  expect(made.store.biometricPromptCount()).toBe(before + 1);
  expect(signed.document.kind).toBe('dnsauth#signedZone');
  expect(signed.document.rrsets.some(rr => rr.type === 'RRSIG')).toBe(true);
  expect(signed.document.rrsets.find(rr => rr.type === 'URI')?.name).toBe('example.test.');
  expect(signed.document.rrsets.find(rr => rr.type === 'WALLET')?.rrdatas).toHaveLength(2);
  verifySignedZone(signed.document, NOW);
  const weekly = await signZone({
    ...material(),
    ksk: made.ksk,
    zsk: made.zsk,
    serial: NOW + 10,
    resignDnskey: false,
    existingDnskeySignatures: signed.dnskeySignatureRrdatas,
  });
  expect(made.store.biometricPromptCount()).toBe(before + 1);
  expect(weekly.dnskeySignatureRrdatas).toEqual(signed.dnskeySignatureRrdatas);
  verifySignedZone(weekly.document, NOW + 10);
});

test('KSK and ZSK are independent', async () => {
  const made = await keys();
  expect(made.ksk.publicRaw).not.toEqual(made.zsk.publicRaw);
});

test('wallet lookup answers yes, no, and cannot verify without trusting AD', async () => {
  const parent = await keys();
  const child = await keys();
  const childSigned = await signZone({ ...material(), ksk: child.ksk, zsk: child.zsk });
  const childKey = dnskeyRdata(257, child.ksk.publicRaw);
  const ds = { ...dsFromDnskey('example.test', childKey, 2), owner: 'example.test' };
  const parentSigned = await signZone({
    ...material({
      apex: 'test',
      rname: 'hostmaster.test',
      uri: [],
      wallet: [],
      ds: [ds],
    }),
    ksk: parent.ksk,
    zsk: parent.zsk,
  });
  const anchor = anchorFor('test', parent.ksk.publicRaw);
  const client = fixtureClient([parentSigned.document, childSigned.document]);
  const resolver = new DnssecResolver(client, NOW, [anchor]);
  const chain = await resolver.resolve('example.test');
  expect(chain.status).toBe('secure');

  const yes = await lookupWallet(
    { domain: 'example.test', type: 'btc', identifier: 'bc1qexample' },
    client,
    NOW,
    [anchor],
  );
  expect(yes.result).toBe('yes');
  expect(yes.validated).toBe(true);

  const no = await lookupWallet(
    { domain: 'example.test', type: 'btc', identifier: 'other' },
    client,
    NOW,
    [anchor],
  );
  expect(no.result).toBe('no');

  const tampered = fixtureClient([parentSigned.document, childSigned.document], { tamper: 'WALLET', ad: true });
  const bad = await lookupWallet(
    { domain: 'example.test', type: 'btc', identifier: 'bc1qexample' },
    tampered,
    NOW,
    [anchor],
  );
  expect(bad.result).toBe('cant_verify');
  expect(bad.validated).toBe(false);

  const info = await lookupDomain('example.test', client, NOW, undefined, [anchor]);
  expect(info.dnssec.validated).toBe(true);
  expect(info.uris.map(uri => uri.target)).toEqual([
    'https://home.example',
    'https://social.example',
    'https://game.example',
  ]);
  expect(info.uris[0].categoryLabel).toBe('default');
  expect(info.wallets.map(wallet => wallet.type)).toEqual(['paypal', 'btc']);
});

function dnskeyRdata(flags: number, raw: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + raw.length);
  out[0] = (flags >> 8) & 255;
  out[1] = flags & 255;
  out[2] = 3;
  out[3] = 13;
  out.set(raw, 4);
  return out;
}

function anchorFor(zone: string, publicRawKey: Uint8Array): TrustAnchor {
  const rdata = dnskeyRdata(257, publicRawKey);
  const ds = dsFromDnskey(zone, rdata, 2);
  let hex = '';
  for (const b of ds.digest) {
    hex += b.toString(16).padStart(2, '0');
  }
  return {
    zone,
    keyTag: ds.keyTag,
    algorithm: 13,
    digestType: 2,
    digestHex: hex,
    flags: 257,
    publicKeyBase64: '',
  };
}

function fixtureClient(docs: ZoneDocument[], options?: { tamper?: string; ad?: boolean }): DohClient {
  return {
    async query(name: string, type: string): Promise<DohMessage> {
      const typeNum = typeCode(type);
      const owner = name.replace(/\.$/, '').toLowerCase();
      const answer: WireRr[] = [];
      for (const doc of docs) {
        for (const rr of doc.rrsets) {
          const rrOwner = rr.name.replace(/\.$/, '').toLowerCase();
          if (rrOwner !== owner) {
            continue;
          }
          if (rr.type === 'RRSIG') {
            for (const text of rr.rrdatas) {
              const parsed = parseRrsig(text);
              if (parsed.typeCovered !== typeNum) {
                continue;
              }
              answer.push(wire(rr.name, TYPE_CODE.RRSIG, rr.ttl, text));
            }
          } else if (typeCode(rr.type) === typeNum) {
            for (const text of rr.rrdatas) {
              const record = wire(rr.name, typeNum, rr.ttl, text);
              if (options?.tamper === rr.type && record.rdata.length > 8) {
                record.rdata = record.rdata.slice();
                record.rdata[8] ^= 0xff;
              }
              answer.push(record);
            }
          }
        }
      }
      return { status: 0, ad: Boolean(options?.ad), answer, authority: [], source: 'primary' };
    },
  };
}

function wire(name: string, type: number, ttl: number, text: string): WireRr {
  return { name, type, ttl, rdata: presentationToRdata(type, text), text };
}

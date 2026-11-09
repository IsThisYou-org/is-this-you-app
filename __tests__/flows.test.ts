import { AppController } from '../src/app/controller';
import { killSwitchCopy } from '../src/killswitch';
import { SoftwareKeystore } from '@isthisyou/keystore';

function memory() {
  const data = new Map<string, string>();
  return {
    async getItem(key: string) {
      return data.get(key) ?? null;
    },
    async setItem(key: string, value: string) {
      data.set(key, value);
    },
  };
}

test('two domains keep separate keys, and a stale serial is re-signed without another biometric', async () => {
  const store = new SoftwareKeystore();
  let now = 1_800_000_000;
  const posts: unknown[] = [];
  let failOnce = true;
  const fetchImpl = async (_url: string, init?: { body?: string }) => {
    const body = JSON.parse(init?.body ?? '{}') as { rrsets: { type: string; rrdatas: string[] }[] };
    posts.push(body);
    const soa = body.rrsets.find(rr => rr.type === 'SOA')?.rrdatas[0] ?? '';
    const serial = Number(soa.split(/\s+/)[2]);
    if (failOnce) {
      failOnce = false;
      return {
        ok: false,
        status: 422,
        async json() {
          return { error: 'serial_stale', message: 'SOA serial is outside the freshness window' };
        },
        async text() {
          return '';
        },
      };
    }
    return {
      ok: true,
      status: 200,
      async json() {
        return { serial, catalogUpdated: true };
      },
      async text() {
        return '';
      },
    };
  };
  const app = new AppController(store, memory(), fetchImpl as never, () => now);
  await app.addDomain('one.example');
  await app.addDomain('two.example');
  await app.generateKeys('one.example');
  await app.generateKeys('two.example');
  expect(app.getDomain('one.example').ksk?.alias).not.toBe(app.getDomain('two.example').ksk?.alias);
  const prompts = store.biometricPromptCount();
  await app.signAndUpload('one.example');
  expect(store.biometricPromptCount()).toBe(prompts + 1);
  expect(posts.length).toBe(2);
  expect(app.getDomain('one.example').lastUpload?.serial).toBeGreaterThan(0);
  expect(app.getDomain('two.example').lastUpload).toBeNull();

  now += 8 * 24 * 60 * 60;
  const due = await app.resignDueDomains();
  expect(due).toEqual(['one.example']);
  expect(store.biometricPromptCount()).toBe(prompts + 1);
});

test('kill switch copy explains DS withdrawal and that it is not instant', () => {
  const copy = killSwitchCopy('one.example', 'one.example. IN DS 1 13 2 ab');
  const text = [...copy.steps, ...copy.warnings, copy.effect].join(' ');
  expect(text).toMatch(/not instant|minutes/i);
  expect(text).toMatch(/empty zone is not a substitute/i);
  expect(text).toMatch(/DS/);
});

import { bundledCatalog, parseCatalog, refreshCatalog } from '../src/catalog';
import {
  compareUris,
  compareWallets,
  encodeWalletRdata,
  isDefaultUri,
  nominateDefault,
  parseWalletRdata,
  publishUri,
  sortUris,
  sortWallets,
  uriCategoryLabel,
} from '../src/records';
import type { CatalogStore } from '../src/catalog';

function memoryStore(initial?: string): CatalogStore & { raw: () => string | null } {
  let value = initial ?? null;
  return {
    async getItem() {
      return value;
    },
    async setItem(_key, next) {
      value = next;
    },
    raw: () => value,
  };
}

function jsonResponse(body: unknown, ok = true) {
  return {
    ok,
    status: ok ? 200 : 500,
    async json() {
      return body;
    },
  };
}

const newer = {
  version: 2,
  uri_categories: [
    { id: 1, name: 'social' },
    { id: 2, name: 'gaming' },
    { id: 3, name: 'music' },
  ],
  wallet_types: [
    { id: 'paypal', name: 'PayPal', identifier_hint: 'account id' },
    { id: 'btc', name: 'Bitcoin', identifier_hint: 'address' },
  ],
};

describe('category catalog', () => {
  test('bundled file has no category 0 and version 1', () => {
    const bundled = bundledCatalog();
    expect(bundled.version).toBe(1);
    expect(bundled.uriCategories.map(category => category.id)).toEqual([1, 2]);
    expect(bundled.uriCategories.some(category => category.id < 1)).toBe(false);
    expect(bundled.walletTypes.map(item => item.id)).toContain('paypal');
  });

  test('rejects category 0, bad versions, and duplicate ids', () => {
    expect(
      parseCatalog({
        version: 2,
        uri_categories: [{ id: 0, name: 'nope' }],
        wallet_types: [],
      }),
    ).toBeNull();
    expect(
      parseCatalog({
        version: '2',
        uri_categories: [],
        wallet_types: [],
      }),
    ).toBeNull();
    expect(
      parseCatalog({
        version: 2,
        uri_categories: [
          { id: 1, name: 'social' },
          { id: 1, name: 'again' },
        ],
        wallet_types: [],
      }),
    ).toBeNull();
    expect(parseCatalog('not json')).toBeNull();
  });

  test('stores a higher version and ignores an equal or older one', async () => {
    const store = memoryStore();
    const calls: string[] = [];
    const fetchImpl = async (url: string) => {
      calls.push(url);
      return jsonResponse(newer);
    };
    const first = await refreshCatalog({
      url: 'https://isthisyou.org/categories.json',
      now: 1_000_000,
      store,
      fetchImpl,
    });
    expect(first.source).toBe('network');
    expect(first.catalog.version).toBe(2);
    expect(first.catalog.uriCategories.map(category => category.name)).toContain('music');

    const same = await refreshCatalog({
      url: 'https://isthisyou.org/categories.json',
      now: 1_000_000 + 86_400,
      store,
      fetchImpl: async () => jsonResponse(newer),
    });
    expect(same.source).toBe('cache');
    expect(same.catalog.version).toBe(2);

    const older = await refreshCatalog({
      url: 'https://isthisyou.org/categories.json',
      now: 1_000_000 + 86_400 * 2,
      store,
      fetchImpl: async () =>
        jsonResponse({
          version: 1,
          uri_categories: [{ id: 9, name: 'should-not-apply' }],
          wallet_types: [],
        }),
    });
    expect(older.catalog.version).toBe(2);
    expect(older.catalog.uriCategories.some(category => category.id === 9)).toBe(false);
    expect(calls).toEqual(['https://isthisyou.org/categories.json']);
  });

  test('does not fetch again until a day has passed', async () => {
    const store = memoryStore();
    let calls = 0;
    const fetchImpl = async () => {
      calls += 1;
      return jsonResponse(newer);
    };
    await refreshCatalog({ now: 5_000, store, fetchImpl });
    await refreshCatalog({ now: 5_000 + 3_600, store, fetchImpl });
    expect(calls).toBe(1);
    await refreshCatalog({ now: 5_000 + 86_400, store, fetchImpl });
    expect(calls).toBe(2);
  });

  test('falls back to the bundle when the network fails or the JSON is invalid', async () => {
    const store = memoryStore();
    const broken = await refreshCatalog({
      now: 10,
      store,
      fetchImpl: async () => {
        throw new Error('offline');
      },
    });
    expect(broken.source).toBe('bundled');
    expect(broken.catalog.version).toBe(1);

    const invalid = await refreshCatalog({
      now: 10 + 86_400,
      store,
      fetchImpl: async () => jsonResponse({ version: 4, uri_categories: 'nope' }),
    });
    expect(invalid.source).toBe('bundled');
    expect(invalid.catalog.version).toBe(1);
    const saved = JSON.parse(store.raw() ?? '{}') as { catalog: unknown };
    expect(parseCatalog(saved.catalog)).toBeNull();
  });

  test('uses the cached copy when a later fetch fails', async () => {
    const store = memoryStore();
    await refreshCatalog({
      now: 100,
      store,
      fetchImpl: async () => jsonResponse(newer),
    });
    const again = await refreshCatalog({
      now: 100 + 86_400,
      store,
      fetchImpl: async () => {
        throw new Error('timeout');
      },
    });
    expect(again.source).toBe('cache');
    expect(again.catalog.version).toBe(2);
    expect(store.raw()).toContain('"version":2');
  });

  test('refuses a non-HTTPS URL and keeps the local copy', async () => {
    let called = false;
    const result = await refreshCatalog({
      url: 'http://isthisyou.org/categories.json',
      now: 50,
      fetchImpl: async () => {
        called = true;
        return jsonResponse(newer);
      },
    });
    expect(called).toBe(false);
    expect(result.source).toBe('bundled');
  });
});

describe('URI and WALLET records', () => {
  const catalog = bundledCatalog();

  test('sorts the default URI first, then category, then weight', () => {
    const sorted = sortUris([
      { priority: 2, weight: 1, target: 'https://game.example' },
      { priority: 1, weight: 5, target: 'https://late.example' },
      { priority: 0, weight: 0, target: 'https://home.example' },
      { priority: 1, weight: 1, target: 'https://social.example' },
      { priority: 9, weight: 0, target: 'https://other.example' },
    ]);
    expect(sorted.map(record => record.target)).toEqual([
      'https://home.example',
      'https://social.example',
      'https://late.example',
      'https://game.example',
      'https://other.example',
    ]);
    expect(isDefaultUri(sorted[0])).toBe(true);
    expect(uriCategoryLabel(catalog, 0, 0)).toBe('default');
    expect(uriCategoryLabel(catalog, 1, 3)).toBe('social');
    expect(uriCategoryLabel(catalog, 2, 1)).toBe('gaming');
    expect(uriCategoryLabel(catalog, 9, 0)).toBe('other');
    expect(uriCategoryLabel(catalog, 0, 4)).toBe('other');
  });

  test('nominating a default clears the previous one', () => {
    const rows = nominateDefault(
      [
        { target: 'a', category: 1, sort: 1, isDefault: true },
        { target: 'b', category: 2, sort: 1, isDefault: false },
      ],
      1,
    );
    expect(rows.filter(row => row.isDefault)).toHaveLength(1);
    expect(rows[1].isDefault).toBe(true);
    expect(rows[0].category).toBe(1);
    const published = rows.map(row =>
      row.isDefault
        ? { priority: 0, weight: 0, target: row.target }
        : { priority: row.category, weight: row.sort, target: row.target },
    );
    expect(published.filter(isDefaultUri)).toHaveLength(1);
  });

  test('publishUri uses 0/0 only for the nominated default', () => {
    expect(publishUri({ target: 'https://home', category: 2, sort: 4, isDefault: true })).toEqual({
      priority: 0,
      weight: 0,
      target: 'https://home',
    });
    expect(publishUri({ target: 'https://social', category: 1, sort: 3, isDefault: false })).toEqual({
      priority: 1,
      weight: 3,
      target: 'https://social',
    });
  });

  test('parses a two-string WALLET and sorts it after numbered records', () => {
    const two = parseWalletRdata(encodeWalletRdata({ type: 'BTC', identifier: 'bc1qexample' }));
    expect(two).toEqual({
      type: 'btc',
      identifier: 'bc1qexample',
      description: null,
      sort: null,
    });
    const four = parseWalletRdata(
      encodeWalletRdata({
        type: 'paypal',
        identifier: 'ABCD1234EFGH5',
        description: 'shop',
        sort: 1,
      }),
    );
    expect(four).toEqual({
      type: 'paypal',
      identifier: 'ABCD1234EFGH5',
      description: 'shop',
      sort: 1,
    });
    const invalidSort = parseWalletRdata(
      Uint8Array.from([
        ...encodeWalletRdata({
          type: 'eth',
          identifier: '0xabc',
          description: 'cold',
          sort: 0,
        }).slice(0, -1),
        'x'.charCodeAt(0),
      ]),
    );
    expect(invalidSort?.sort).toBeNull();
    const ordered = sortWallets([
      two!,
      { type: 'eth', identifier: '0xabc', description: null, sort: 5 },
      four!,
    ]);
    expect(ordered.map(item => item.type)).toEqual(['paypal', 'eth', 'btc']);
    expect(compareWallets(ordered[2], ordered[0])).toBeGreaterThan(0);
  });
});

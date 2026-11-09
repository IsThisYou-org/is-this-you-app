import bundledFile from '../data/categories.json';

/**
 * Display names for URI categories and wallet types.
 *
 * The master file is maintained in https://github.com/james-stevens/IsThisYou.org
 * and served at https://isthisyou.org/categories.json. This package only ships
 * an offline copy. Nothing here is signed; it is display data.
 */

export const DEFAULT_CATALOG_URL = 'https://isthisyou.org/categories.json';
export const CATALOG_CACHE_KEY = 'isthisyou.categories.cache.v1';
export const CATALOG_MAX_AGE_SECONDS = 24 * 60 * 60;

export interface UriCategory {
  id: number;
  name: string;
}

export interface WalletTypeInfo {
  id: string;
  name: string;
  identifierHint: string;
}

export interface CategoryCatalog {
  version: number;
  uriCategories: UriCategory[];
  walletTypes: WalletTypeInfo[];
}

export interface CatalogStore {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
}

interface CacheEnvelope {
  checkedAt: number;
  catalog: CategoryCatalog | null;
}

export interface FetchLike {
  (url: string, init?: { headers?: Record<string, string> }): Promise<{
    ok: boolean;
    status: number;
    json: () => Promise<unknown>;
  }>;
}

export interface RefreshCatalogOptions {
  url?: string;
  now?: number;
  store?: CatalogStore;
  fetchImpl?: FetchLike;
  /** How long after a check before another network attempt. Default one day. */
  minIntervalSeconds?: number;
}

export interface RefreshCatalogResult {
  catalog: CategoryCatalog;
  source: 'bundled' | 'cache' | 'network';
}

export function parseCatalog(value: unknown): CategoryCatalog | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }
  const raw = value as Record<string, unknown>;
  if (!Number.isInteger(raw.version) || (raw.version as number) < 1) {
    return null;
  }
  if (!Array.isArray(raw.uri_categories) || !Array.isArray(raw.wallet_types)) {
    return null;
  }
  const uriCategories: UriCategory[] = [];
  const seenCategories = new Set<number>();
  for (const item of raw.uri_categories) {
    if (!item || typeof item !== 'object') {
      return null;
    }
    const row = item as Record<string, unknown>;
    if (!Number.isInteger(row.id) || (row.id as number) < 1) {
      return null;
    }
    if (typeof row.name !== 'string' || row.name.trim() === '') {
      return null;
    }
    if (seenCategories.has(row.id as number)) {
      return null;
    }
    seenCategories.add(row.id as number);
    uriCategories.push({ id: row.id as number, name: row.name.trim() });
  }
  const walletTypes: WalletTypeInfo[] = [];
  const seenTypes = new Set<string>();
  for (const item of raw.wallet_types) {
    if (!item || typeof item !== 'object') {
      return null;
    }
    const row = item as Record<string, unknown>;
    if (typeof row.id !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,31}$/i.test(row.id)) {
      return null;
    }
    if (typeof row.name !== 'string' || row.name.trim() === '') {
      return null;
    }
    if (
      row.identifier_hint != null &&
      typeof row.identifier_hint !== 'string'
    ) {
      return null;
    }
    const id = row.id.trim().toLowerCase();
    if (seenTypes.has(id)) {
      return null;
    }
    seenTypes.add(id);
    walletTypes.push({
      id,
      name: row.name.trim(),
      identifierHint:
        typeof row.identifier_hint === 'string' ? row.identifier_hint.trim() : '',
    });
  }
  return {
    version: raw.version as number,
    uriCategories,
    walletTypes,
  };
}

export function bundledCatalog(): CategoryCatalog {
  const parsed = parseCatalog(bundledFile);
  if (!parsed) {
    throw new Error('The bundled categories file is invalid');
  }
  return parsed;
}

async function readCache(store: CatalogStore | undefined): Promise<CacheEnvelope | null> {
  if (!store) {
    return null;
  }
  try {
    const raw = await store.getItem(CATALOG_CACHE_KEY);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as { checkedAt?: unknown; catalog?: unknown };
    const checkedAt =
      typeof parsed.checkedAt === 'number' && Number.isFinite(parsed.checkedAt)
        ? parsed.checkedAt
        : 0;
    return { checkedAt, catalog: parseCatalog(parsed.catalog) };
  } catch {
    return null;
  }
}

/**
 * Load the display catalog.
 *
 * A network copy is kept only when its version is greater than the bundled
 * file and any cached copy. Errors, invalid JSON, and non-HTTPS URLs leave
 * the previous copy in place. Checks are at most once a day.
 */
export async function refreshCatalog(
  options: RefreshCatalogOptions = {},
): Promise<RefreshCatalogResult> {
  const bundled = bundledCatalog();
  const cache = await readCache(options.store);
  let catalog = bundled;
  let source: RefreshCatalogResult['source'] = 'bundled';
  if (cache?.catalog && cache.catalog.version > bundled.version) {
    catalog = cache.catalog;
    source = 'cache';
  }

  const now = options.now ?? Math.floor(Date.now() / 1000);
  const interval = options.minIntervalSeconds ?? CATALOG_MAX_AGE_SECONDS;
  const checkedAt = cache?.checkedAt ?? 0;
  if (checkedAt > 0 && now - checkedAt < interval) {
    return { catalog, source };
  }

  const url = options.url ?? DEFAULT_CATALOG_URL;
  const fetchImpl =
    options.fetchImpl ?? (globalThis.fetch as FetchLike | undefined);
  const writeCache = async (wireCatalog: unknown | null) => {
    if (!options.store) {
      return;
    }
    await options.store.setItem(
      CATALOG_CACHE_KEY,
      JSON.stringify({ checkedAt: now, catalog: wireCatalog }),
    );
  };

  if (!fetchImpl || !url.startsWith('https://')) {
    await writeCache(cache?.catalog ? toWire(cache.catalog) : null);
    return { catalog, source };
  }

  try {
    const response = await fetchImpl(url, {
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const body = await response.json();
    const parsed = parseCatalog(body);
    if (parsed && parsed.version > catalog.version) {
      await writeCache(body);
      return { catalog: parsed, source: 'network' };
    }
    await writeCache(cache?.catalog ? toWire(cache.catalog) : null);
    return { catalog, source };
  } catch {
    await writeCache(cache?.catalog ? toWire(cache.catalog) : null);
    return { catalog, source };
  }
}

function toWire(catalog: CategoryCatalog): unknown {
  return {
    version: catalog.version,
    uri_categories: catalog.uriCategories.map(category => ({
      id: category.id,
      name: category.name,
    })),
    wallet_types: catalog.walletTypes.map(item => ({
      id: item.id,
      name: item.name,
      identifier_hint: item.identifierHint,
    })),
  };
}

export function uriCategoryLabel(
  catalog: CategoryCatalog,
  priority: number,
  weight: number,
): string {
  if (priority === 0 && weight === 0) {
    return 'default';
  }
  const found = catalog.uriCategories.find(category => category.id === priority);
  return found ? found.name : 'other';
}

export function walletTypeLabel(catalog: CategoryCatalog, type: string): string {
  const found = catalog.walletTypes.find(
    item => item.id === type.trim().toLowerCase(),
  );
  return found ? found.name : type.trim();
}

export function walletTypeHint(catalog: CategoryCatalog, type: string): string {
  const found = catalog.walletTypes.find(
    item => item.id === type.trim().toLowerCase(),
  );
  return found?.identifierHint ?? '';
}

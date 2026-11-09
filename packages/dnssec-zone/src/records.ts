import { utf8Encode } from './bytes';
import type { CategoryCatalog } from './catalog';
import { uriCategoryLabel, walletTypeLabel } from './catalog';
import { presentCharString } from './presentation';
import { Writer } from './writer';

export { uriCategoryLabel, walletTypeLabel };

/** Priority 0 and weight 0 together. Not a category. */
export function isDefaultUri(record: {
  priority: number;
  weight: number;
}): boolean {
  return record.priority === 0 && record.weight === 0;
}

export interface UriRecord {
  priority: number;
  weight: number;
  target: string;
}

/**
 * One default per zone. Priority 0 is rejected unless the weight is also 0.
 * Categories are integers starting at 1.
 */
export function assertUriSet(records: UriRecord[]): void {
  let defaults = 0;
  for (const record of records) {
    if (!Number.isInteger(record.priority) || !Number.isInteger(record.weight)) {
      throw new Error('URI priority and weight must be integers');
    }
    if (record.priority < 0 || record.priority > 65535 || record.weight < 0 || record.weight > 65535) {
      throw new Error('URI priority and weight must fit in 16 bits');
    }
    if (record.target.trim() === '') {
      throw new Error('URI target is empty');
    }
    if (isDefaultUri(record)) {
      defaults += 1;
    } else if (record.priority === 0) {
      throw new Error('Priority 0 is reserved for the default URI (weight 0)');
    } else if (record.priority < 1) {
      throw new Error('URI categories start at 1');
    }
  }
  if (defaults > 1) {
    throw new Error('A zone can nominate only one default URI');
  }
}

/** Default first, then category number, then weight, then target. */
export function compareUris(a: UriRecord, b: UriRecord): number {
  const aDefault = isDefaultUri(a);
  const bDefault = isDefaultUri(b);
  if (aDefault !== bDefault) {
    return aDefault ? -1 : 1;
  }
  if (a.priority !== b.priority) {
    return a.priority - b.priority;
  }
  if (a.weight !== b.weight) {
    return a.weight - b.weight;
  }
  if (a.target < b.target) {
    return -1;
  }
  if (a.target > b.target) {
    return 1;
  }
  return 0;
}

export function sortUris(records: UriRecord[]): UriRecord[] {
  return [...records].sort(compareUris);
}

export interface EditableUri {
  target: string;
  /** Used when this row is not the default. Must be >= 1. */
  category: number;
  /** Weight / sort order when this row is not the default. Lower first. */
  sort: number;
  isDefault: boolean;
}

/** Nominating a row clears the previous default. Category data on the old default is kept. */
export function nominateDefault<T extends { isDefault: boolean }>(
  records: T[],
  index: number,
): T[] {
  return records.map((record, i) => ({ ...record, isDefault: i === index }));
}

export function publishUri(record: EditableUri): UriRecord {
  if (record.isDefault) {
    return { priority: 0, weight: 0, target: record.target };
  }
  if (!Number.isInteger(record.category) || record.category < 1) {
    throw new Error('URI categories start at 1');
  }
  return {
    priority: record.category,
    weight: record.sort,
    target: record.target,
  };
}

export interface WalletFields {
  type: string;
  identifier: string;
  description?: string;
  /** Omit, or pass a non-integer, to sort last. */
  sort?: number | null;
}

export interface ParsedWallet {
  type: string;
  identifier: string;
  description: string | null;
  /** null means the record did not carry a usable sort order. */
  sort: number | null;
}

const SORT_LAST = Number.POSITIVE_INFINITY;

function characterString(value: string): Uint8Array {
  const bytes = utf8Encode(value);
  if (bytes.length > 255) {
    throw new Error('WALLET field is longer than 255 bytes');
  }
  const out = new Uint8Array(bytes.length + 1);
  out[0] = bytes.length;
  out.set(bytes, 1);
  return out;
}

export function encodeWalletRdata(wallet: WalletFields): Uint8Array {
  const type = wallet.type.trim().toLowerCase();
  const identifier = wallet.identifier.trim();
  if (!type || !identifier) {
    throw new Error('WALLET type and identifier are required');
  }
  const parts = [characterString(type), characterString(identifier)];
  const description = wallet.description?.trim() ?? '';
  const hasSort = wallet.sort != null && Number.isInteger(wallet.sort);
  if (description || hasSort) {
    parts.push(characterString(description));
  }
  if (hasSort) {
    parts.push(characterString(String(wallet.sort)));
  }
  const w = new Writer();
  for (const part of parts) {
    w.bytes(part);
  }
  return w.concat();
}

export function readCharacterStrings(rdata: Uint8Array): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < rdata.length) {
    const len = rdata[i++];
    if (i + len > rdata.length) {
      throw new Error('Truncated character-string');
    }
    let text = '';
    for (const b of rdata.subarray(i, i + len)) {
      text += String.fromCharCode(b);
    }
    out.push(text);
    i += len;
  }
  return out;
}

function parseSortText(value: string | undefined): number | null {
  if (value == null) {
    return null;
  }
  const trimmed = value.trim();
  if (!/^-?\d+$/.test(trimmed)) {
    return null;
  }
  return Number(trimmed);
}

/** Two strings are enough. A third is a description. A fourth is a sort order. */
export function parseWalletStrings(parts: string[]): ParsedWallet | null {
  if (parts.length < 2) {
    return null;
  }
  const type = parts[0].trim().toLowerCase();
  const identifier = parts[1].trim();
  if (!type || !identifier) {
    return null;
  }
  const description = parts.length >= 3 && parts[2].trim() !== '' ? parts[2].trim() : null;
  const sort = parts.length >= 4 ? parseSortText(parts[3]) : null;
  return { type, identifier, description, sort };
}

export function parseWalletRdata(rdata: Uint8Array): ParsedWallet | null {
  try {
    return parseWalletStrings(readCharacterStrings(rdata));
  } catch {
    return null;
  }
}

export function presentWallet(wallet: WalletFields): string {
  const encoded = encodeWalletRdata(wallet);
  return readCharacterStrings(encoded).map(text => presentCharString(utf8Encode(text))).join(' ');
}

export function compareWallets(a: ParsedWallet, b: ParsedWallet): number {
  const as = a.sort == null ? SORT_LAST : a.sort;
  const bs = b.sort == null ? SORT_LAST : b.sort;
  if (as !== bs) {
    return as < bs ? -1 : 1;
  }
  if (a.type !== b.type) {
    return a.type < b.type ? -1 : 1;
  }
  if (a.identifier < b.identifier) {
    return -1;
  }
  if (a.identifier > b.identifier) {
    return 1;
  }
  return 0;
}

export function sortWallets(records: ParsedWallet[]): ParsedWallet[] {
  return [...records].sort(compareWallets);
}

export function walletIdsMatch(
  published: ParsedWallet,
  query: { type: string; identifier: string },
): boolean {
  if (published.type !== query.type.trim().toLowerCase()) {
    return false;
  }
  const left = published.identifier.trim();
  const right = query.identifier.trim();
  if (left.includes('@') || right.includes('@')) {
    return left.toLowerCase() === right.toLowerCase();
  }
  return left === right;
}

export function describeWalletType(
  catalog: CategoryCatalog,
  type: string,
): { label: string; known: boolean; hint: string } {
  const known = catalog.walletTypes.some(item => item.id === type.trim().toLowerCase());
  return {
    label: walletTypeLabel(catalog, type),
    known,
    hint: catalog.walletTypes.find(item => item.id === type.trim().toLowerCase())
      ?.identifierHint ?? '',
  };
}

/** PayPal's published identifier is a 13-character account id unless the user opts into an email. */
export function paypalIdentifierError(
  identifier: string,
  useEmail: boolean,
): string | null {
  const value = identifier.trim();
  if (useEmail) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
      return 'Enter the PayPal email address to publish.';
    }
    return null;
  }
  if (!/^[A-Za-z0-9]{13}$/.test(value)) {
    return 'PayPal account IDs are 13 letters or digits. Choose email only if you mean to publish an address.';
  }
  return null;
}

export const PAYPAL_EMAIL_WARNING =
  'A PayPal email address published in DNS is public forever. Spammers can scrape it. Prefer the 13-character payer or merchant ID.';

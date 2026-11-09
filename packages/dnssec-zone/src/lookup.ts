import type { CategoryCatalog } from './catalog';
import { bundledCatalog, uriCategoryLabel, walletTypeLabel } from './catalog';
import type { DohClient } from './doh';
import {
  compareUris,
  compareWallets,
  isDefaultUri,
  parseWalletRdata,
  readCharacterStrings,
  walletIdsMatch,
  type ParsedWallet,
  type UriRecord,
} from './records';
import { TYPE_CODE } from './types';
import type { TrustAnchor } from './anchors';
import { DnssecResolver, type ChainStatus } from './validate';
import { presentationToRdata } from './wire';

export interface WalletQuery {
  domain: string;
  type: string;
  identifier: string;
}

export type WalletAnswer =
  | {
      result: 'yes' | 'no';
      validated: true;
      reason: string;
      chain: string[];
      matches: ParsedWallet[];
    }
  | {
      result: 'cant_verify';
      validated: false;
      reason: string;
      chain: string[];
      matches: ParsedWallet[];
    };

export interface DomainReport {
  domain: string;
  dnssec: {
    status: ChainStatus;
    validated: boolean;
    reason: string;
    chain: string[];
  };
  uris: Array<UriRecord & { categoryLabel: string }>;
  wallets: Array<ParsedWallet & { typeLabel: string }>;
}

export async function lookupWallet(
  query: WalletQuery,
  client: DohClient,
  now: number,
  anchors?: TrustAnchor[],
): Promise<WalletAnswer> {
  const resolver = new DnssecResolver(client, now, anchors);
  const chain = await resolver.resolve(query.domain);
  if (chain.status !== 'secure' || !sameName(chain.zone, query.domain)) {
    return {
      result: 'cant_verify',
      validated: false,
      reason:
        chain.status === 'insecure'
          ? chain.reason
          : chain.reason || 'DNSSEC chain did not validate',
      chain: chain.chain,
      matches: [],
    };
  }
  const proof = await resolver.prove(query.domain, TYPE_CODE.WALLET, chain.keys, chain.zone);
  if (!proof.validated) {
    return {
      result: 'cant_verify',
      validated: false,
      reason: proof.reason,
      chain: chain.chain,
      matches: [],
    };
  }
  const wallets = proof.records
    .map(rr => parseWalletRdata(rr.rdata))
    .filter((item): item is ParsedWallet => item != null);
  const matches = wallets.filter(item =>
    walletIdsMatch(item, { type: query.type, identifier: query.identifier }),
  );
  if (matches.length > 0) {
    return {
      result: 'yes',
      validated: true,
      reason: `${query.type} ${query.identifier} is published in the signed WALLET set`,
      chain: chain.chain,
      matches,
    };
  }
  if (proof.denial || wallets.length >= 0) {
    return {
      result: 'no',
      validated: true,
      reason: proof.denial
        ? 'The signed zone has no WALLET records'
        : 'The signed WALLET set does not contain that type and identifier',
      chain: chain.chain,
      matches: [],
    };
  }
  return {
    result: 'cant_verify',
    validated: false,
    reason: proof.reason,
    chain: chain.chain,
    matches: [],
  };
}

export async function lookupDomain(
  domain: string,
  client: DohClient,
  now: number,
  catalog: CategoryCatalog = bundledCatalog(),
  anchors?: TrustAnchor[],
): Promise<DomainReport> {
  const resolver = new DnssecResolver(client, now, anchors);
  const chain = await resolver.resolve(domain);
  const report: DomainReport = {
    domain,
    dnssec: {
      status: chain.status,
      validated: chain.status === 'secure' && sameName(chain.zone, domain),
      reason: chain.reason,
      chain: chain.chain,
    },
    uris: [],
    wallets: [],
  };
  if (!report.dnssec.validated) {
    return report;
  }
  const uris = await resolver.prove(domain, TYPE_CODE.URI, chain.keys, chain.zone);
  if (uris.validated && !uris.denial) {
    report.uris = uris.records
      .map(rr => parseUriRdata(rr.rdata))
      .filter((item): item is UriRecord => item != null)
      .sort(compareUris)
      .map(item => ({
        ...item,
        categoryLabel: isDefaultUri(item)
          ? 'default'
          : uriCategoryLabel(catalog, item.priority, item.weight),
      }));
  }
  const wallets = await resolver.prove(domain, TYPE_CODE.WALLET, chain.keys, chain.zone);
  if (wallets.validated && !wallets.denial) {
    report.wallets = wallets.records
      .map(rr => parseWalletRdata(rr.rdata))
      .filter((item): item is ParsedWallet => item != null)
      .sort(compareWallets)
      .map(item => ({ ...item, typeLabel: walletTypeLabel(catalog, item.type) }));
  }
  return report;
}

function parseUriRdata(rdata: Uint8Array): UriRecord | null {
  if (rdata.length < 5) {
    return null;
  }
  const priority = (rdata[0] << 8) | rdata[1];
  const weight = (rdata[2] << 8) | rdata[3];
  let target = '';
  for (const b of rdata.subarray(4)) {
    target += String.fromCharCode(b);
  }
  return { priority, weight, target };
}

function sameName(zone: string, domain: string): boolean {
  const left = zone === '.' ? '.' : zone.replace(/\.$/, '').toLowerCase();
  const right = domain.replace(/\.$/, '').toLowerCase();
  return left === right;
}

void readCharacterStrings;
void presentationToRdata;

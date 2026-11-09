/**
 * Settled defaults for questions the spec left open.
 * Each domain copies these at creation time and can change its own copy.
 */

export interface DomainSettings {
  uploadBaseUrl: string;
  /** Every public nameserver of the hosting service. The apex NS set is this list. */
  serviceNs: string[];
  /** SOA MNAME. Must be one of serviceNs. */
  mname: string;
  /** Local part of the SOA RNAME mailbox. The zone uses `<local>.<apex>`. */
  rnameLocalPart: string;
  soaRefresh: number;
  soaRetry: number;
  soaExpire: number;
  soaMinimum: number;
  ttl: number;
  rrsigValiditySeconds: number;
  inceptionBackdateSeconds: number;
  /** Expiry is shortened by 0..jitterMaxSeconds, derived from the owner name and type. */
  jitterMaxSeconds: number;
  freshnessMaxAheadSeconds: number;
  freshnessMaxBehindSeconds: number;
  resignIntervalSeconds: number;
  rrsigWarnSeconds: number;
  rrsigCriticalSeconds: number;
  resignOverdueSeconds: number;
  nsecMode: 'nsec3' | 'nsec';
  nsec3Iterations: number;
  /** Empty string means empty salt. Otherwise even-length hex. */
  nsec3SaltHex: string;
  nsec3OptOut: boolean;
  /** DoH JSON resolver. Chain validation uses the rdata field, not the AD bit. */
  dohUrl: string;
  /** Used when the primary resolver rejects a name, notably the DNS root. */
  dohFallbackUrl: string;
  /** Display names. The master file is served from the IsThisYou.org repo. */
  catalogUrl: string;
}

export function defaultSettings(): DomainSettings {
  return {
    uploadBaseUrl: 'http://127.0.0.1:8080',
    serviceNs: ['ns1.example.net.', 'ns2.example.net.'],
    mname: 'ns1.example.net.',
    rnameLocalPart: 'hostmaster',
    soaRefresh: 3600,
    soaRetry: 600,
    soaExpire: 864000,
    soaMinimum: 300,
    ttl: 300,
    rrsigValiditySeconds: 30 * 24 * 60 * 60,
    inceptionBackdateSeconds: 3600,
    jitterMaxSeconds: 3600,
    freshnessMaxAheadSeconds: 5 * 60,
    freshnessMaxBehindSeconds: 60 * 60,
    resignIntervalSeconds: 7 * 24 * 60 * 60,
    rrsigWarnSeconds: 7 * 24 * 60 * 60,
    rrsigCriticalSeconds: 2 * 24 * 60 * 60,
    resignOverdueSeconds: 8 * 24 * 60 * 60,
    nsecMode: 'nsec3',
    nsec3Iterations: 0,
    nsec3SaltHex: '',
    nsec3OptOut: false,
    dohUrl: 'https://api.web3dns.net/',
    dohFallbackUrl: 'https://dns.google/resolve',
    catalogUrl: 'https://isthisyou.org/categories.json',
  };
}

export function cloneSettings(settings: DomainSettings): DomainSettings {
  return {
    ...settings,
    serviceNs: [...settings.serviceNs],
  };
}

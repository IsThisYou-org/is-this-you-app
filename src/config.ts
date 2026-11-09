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
  /** Best-effort parent DS lookup. Not a trust anchor. */
  dohUrl: string;
}

export function defaultSettings(): DomainSettings {
  return {
    uploadBaseUrl: 'http://127.0.0.1:8787',
    serviceNs: ['ns1.dnsauth.local.', 'ns2.dnsauth.local.'],
    mname: 'ns1.dnsauth.local.',
    rnameLocalPart: 'hostmaster',
    soaRefresh: 3600,
    soaRetry: 600,
    soaExpire: 604800,
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
    dohUrl: 'https://cloudflare-dns.com/dns-query',
  };
}

export function cloneSettings(settings: DomainSettings): DomainSettings {
  return {
    ...settings,
    serviceNs: [...settings.serviceNs],
  };
}

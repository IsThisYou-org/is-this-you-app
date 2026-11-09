/**
 * Upload document accepted by the hosting service.
 * RRSIGs are their own rrsets. See is-this-you-dns-host `parse_upload`.
 */
export interface ResourceRecordSet {
  kind: 'dns#resourceRecordSet';
  name: string;
  type: string;
  ttl: number;
  rrdatas: string[];
}

export interface ZoneDocument {
  kind: 'dnsauth#signedZone';
  apex: string;
  rrsets: ResourceRecordSet[];
}

export const TYPE_CODE = {
  A: 1,
  NS: 2,
  SOA: 6,
  TXT: 16,
  DS: 43,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  NSEC3: 50,
  NSEC3PARAM: 51,
  URI: 256,
  /** IANA WALLET. RDATA is character-strings, same framing as TXT. */
  WALLET: 262,
} as const;

export const CODE_TYPE: Record<number, string> = Object.fromEntries(
  Object.entries(TYPE_CODE).map(([name, code]) => [code, name]),
);

export function typeCode(name: string): number {
  const code = TYPE_CODE[name as keyof typeof TYPE_CODE];
  if (!code) {
    throw new Error(`Unsupported RR type ${name}`);
  }
  return code;
}

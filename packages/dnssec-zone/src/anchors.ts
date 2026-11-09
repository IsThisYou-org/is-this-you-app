/**
 * ICANN root trust anchors from https://data.iana.org/root-anchors/root-anchors.xml
 * (the two KSKs that are valid as of November 2026). The package checks DNSKEY
 * RRsets against these digests. It does not treat a resolver AD bit as an anchor.
 */
export interface TrustAnchor {
  /** Zone the anchor authenticates. "." is the ICANN root. */
  zone: string;
  keyTag: number;
  algorithm: number;
  digestType: number;
  /** Lower-case hex, no separators. */
  digestHex: string;
  flags: number;
  /** Base64 of the DNSKEY public-key field (RFC 3110 for algorithm 8). */
  publicKeyBase64: string;
}

export const ROOT_TRUST_ANCHORS: TrustAnchor[] = [
  {
    zone: '.',
    keyTag: 20326,
    algorithm: 8,
    digestType: 2,
    digestHex:
      'e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d',
    flags: 257,
    publicKeyBase64:
      'AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=',
  },
  {
    zone: '.',
    keyTag: 38696,
    algorithm: 8,
    digestType: 2,
    digestHex:
      '683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16',
    flags: 257,
    publicKeyBase64:
      'AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=',
  },
];

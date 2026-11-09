/**
 * Authorisation is intentionally not part of this MVP. The pieces below stay
 * available so a later change can finish them without reshaping zones or keys.
 *
 * - Keystore purposes other than `ksk` and `zsk` are accepted (`site`, `agent`,
 *   `log`, `recovery`) and are not used by the screens.
 * - `attest()` is implemented on the keystore and is not called by zone publish.
 * - The signer takes ordinary TXT and URI records, so a later `_auth.<hash>` TXT
 *   can sit beside wallet TXT.
 * - State is one record per apex. A future request can name the apex it belongs to.
 *
 * Transport, when authorisation is built: a QR code the phone scans, plus a deep
 * link for when the user is already browsing on the phone. No push notifications.
 */
export const DEFERRED_FEATURES = [
  'per-site enrolment',
  'detached JWS authorisation',
  'proof bundles',
  'agent slice',
  'signed request log',
] as const;

export type DeferredFeature = (typeof DEFERRED_FEATURES)[number];

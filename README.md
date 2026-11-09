# Is this you?

Android app for a user-owned DNSSEC identity zone. The phone holds the zone-signing keys, builds and signs the zone, and uploads the signed records to the hosting service. It can also look up any domain's URI and WALLET records and check the DNSSEC chain itself.

iOS is not in this build.

## Packages

- `packages/dnssec-zone` — zone builder, algorithm-13 signer, NSEC3, and the DNSSEC chain checker. No React Native.
- `packages/keystore` — `SoftwareKeystore` for tests, and the Kotlin Android Keystore module (`IsThisYouKeystore`) used by the app.

The app imports those packages. It does not keep a second copy of the signer.

## Display names

URI categories and known wallet types are display-only and are not signed. The master `categories.json` lives in [james-stevens/IsThisYou.org](https://github.com/james-stevens/IsThisYou.org) and is served at https://isthisyou.org/categories.json. This repo only has the offline copy at `packages/dnssec-zone/data/categories.json`.

On startup the app fetches that URL at most once a day. It keeps a response only when `version` is higher than the copy it already has. A network error or invalid JSON leaves the cache, or the bundled file, in place. Schema:

```json
{
  "version": 1,
  "uri_categories": [{ "id": 1, "name": "social" }],
  "wallet_types": [
    { "id": "paypal", "name": "PayPal", "identifier_hint": "13-character payer or merchant ID" }
  ]
}
```

Category ids start at 1. Priority 0 and weight 0 together are the single default URI, not a category. Unknown category numbers are shown as "other". Unknown wallet types are shown with their raw type string.

## Records

- URI records are all at the zone apex. Priority is the category. Weight is the sort order, lower first. At most one URI is the default (`0 0`).
- WALLET (type 262) is character-strings at the apex: type, identifier, and optionally a description and a numeric sort order. A two-string record is valid. A missing or non-numeric sort order sorts last.
- PayPal's identifier is the 13-character account id unless the user explicitly chooses an email. The editor warns that a published email is public permanently.

## Keys

KSK and ZSK are P-256 (DNSSEC algorithm 13). Each domain has its own pair. The KSK is created with user authentication required; signing the DNSKEY set shows `BiometricPrompt`. The ZSK is not gated per signature. The module asks for StrongBox and, if the device has none, generates the key in the TEE and records which one was used. Android 10 (API 29) is the minimum, for the Moto G8 Plus used in development. That phone has no StrongBox, so the TEE path is the one that must work.

`attest` returns the Android Key Attestation certificate chain. Publishing a zone does not call it. There is no relying-party enrolment in this MVP, so the chain is not sent anywhere yet.

This environment cannot open BiometricPrompt or StrongBox. Unit tests use `SoftwareKeystore`, which counts biometric prompts. The debug APK contains the Kotlin module; the prompt runs on a device.

## DNSSEC lookups

Lookups use DNS-over-HTTPS JSON, default `https://api.web3dns.net/?name=&type=&do=1`. Validation uses the `rdata` field (wire RDATA) and ignores the AD bit. `api.web3dns.net` rejects the root name `.`, so the root DNSKEY query falls back to `https://dns.google/resolve` and is still checked against the bundled IANA trust anchors. That fallback URL is a setting.

Wallet check and domain info work for any domain, not only the ones on the phone. A match is yes only when the chain validates. A validated WALLET set that does not contain the type and identifier is no. Anything else is "can't verify".

## Hosting upload

`POST /v1/zones/{apex}` with `Content-Type: application/json`:

```json
{ "kind": "dnsauth#signedZone", "apex": "example.com.", "rrsets": [ { "kind": "dns#resourceRecordSet", "name": "example.com.", "type": "SOA", "ttl": 300, "rrdatas": ["..."] } ] }
```

RRSIGs are their own rrsets. The shape matches [is-this-you-dns-host](https://github.com/james-stevens/is-this-you-dns-host/pull/1). `serial_stale`, `serial_in_future`, and `serial_not_increased` cause one ZSK re-sign and a retry, without asking for the KSK again. SOA serial is Unix time. RRSIG lifetime is at most 30 days measured from the backdated inception, because the host rejects a longer lifetime.

## Build and sideload

Requirements: Node 22, JDK 17 or 21, Android SDK (compileSdk 37). `minSdk` is 29.

```sh
npm install
export ANDROID_HOME="$HOME/android-sdk"
echo "sdk.dir=$ANDROID_HOME" > android/local.properties
npm test
npm run android:assemble
```

The debug APK is `android/app/build/outputs/apk/debug/app-debug.apk`.

```sh
adb reverse tcp:8080 tcp:8080
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```

`adb reverse` makes the phone's `127.0.0.1:8080` the computer running the host. The debug build allows cleartext HTTP. A phone on the same LAN can use the computer's address instead of reverse.

Local stand-in for the host:

```sh
npm run mock-host
```

That listens on port 8080 and speaks the same upload path and serial error codes. Set `MOCK_NOW` to force a stale-serial response. The default nameservers are `ns1.example.net.` and `ns2.example.net.`. Point the domain's hosting settings at the real service NS list before a real upload.

On the phone: add a domain, generate keys, publish the shown DS and every hosting NS at the registrar, then upload. The app does not call the zone live until the host accepts it, and it says resolvers may still SERVFAIL until secondaries AXFR. Weekly re-sign runs when the app is opened, for every domain that is due. There is no background scheduler in this build.

## Not in this MVP

Per-site enrolment, detached JWS, proof bundles, agents, and the signed request log. Authorisation requests, when they are added, will arrive by QR code or a deep link while the user is already on the phone. No push notifications.

On-device biometrics and StrongBox are implemented in the Kotlin module and are not executed in CI.

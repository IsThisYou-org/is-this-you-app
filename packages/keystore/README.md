# @isthisyou/keystore

P-256 keys for the phone app.

`SoftwareKeystore` is an in-process implementation used by tests. It counts biometric prompts and can refuse them. Those keys are exportable. The Android app does not use it for zone keys.

`createAppKeystore` from `@isthisyou/keystore/react-native` talks to the Kotlin module `IsThisYouKeystore`:

- Generate a P-256 key in the Android Keystore.
- Prefer StrongBox (`setIsStrongBoxBacked`). If that throws, generate again in the TEE and record which one was used.
- The KSK is created with user authentication required. `sign` shows a `BiometricPrompt` and signs with the authorised `CryptoObject`. The ZSK is not gated, and `signMany` refuses a biometric key.
- `attest` returns the Android Key Attestation certificate chain. Zone publication does not call it. Enrolment, which would send the chain to a site, is not in this MVP.
- API 29 (Android 10) uses `setUserAuthenticationValidityDurationSeconds(-1)`. API 30 and later use `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`.

This environment cannot run BiometricPrompt or StrongBox. The Kotlin code is compiled into the debug APK; the prompt itself only runs on a device.

export type HardwareTier = 'strongbox' | 'tee' | 'software';

/** `ksk` and `zsk` are used now. The other purposes are reserved for later authorisation work. */
export type KeyPurpose = 'ksk' | 'zsk' | 'site' | 'agent' | 'log' | 'recovery';

export interface KeyRecord {
  alias: string;
  purpose: KeyPurpose;
  hardwareTier: HardwareTier;
  requireBiometric: boolean;
  /** Standard base64 of the SubjectPublicKeyInfo DER. */
  spkiDerBase64: string;
  /** Standard base64 of the 64-byte X || Y DNSKEY public key. */
  publicRawBase64: string;
  createdAt: number;
  /** True for the in-process software keystore. Never true for Android Keystore keys. */
  simulator: boolean;
}

export interface Attestation {
  alias: string;
  purpose: KeyPurpose;
  challengeBase64: string;
  spkiDerBase64: string;
  hardwareTier: HardwareTier;
  simulator: boolean;
  /** Android Key Attestation certificate chain, leaf first, DER base64. Empty for the software keystore. */
  certChainDerBase64: string[];
  attestationError?: string;
  /** Software-keystore stand-in. Not an Android attestation. */
  statementJson?: string;
}

export interface GenerateKeyRequest {
  alias: string;
  purpose: KeyPurpose;
  requireBiometric: boolean;
  attestationChallenge?: Uint8Array;
  /** Android prefers StrongBox and falls back to TEE. Ignored by the software keystore. */
  preferStrongBox?: boolean;
}

export interface HardwareInfo {
  strongBoxAvailable: boolean;
}

/**
 * Private keys stay behind this interface.
 * The Android implementation uses the hardware keystore. Tests use software keys.
 */
export interface Keystore {
  readonly kind: 'android' | 'software';
  generateKey(request: GenerateKeyRequest): Promise<KeyRecord>;
  getKey(alias: string): Promise<KeyRecord | null>;
  listKeys(): Promise<KeyRecord[]>;
  deleteKey(alias: string): Promise<void>;
  /**
   * SHA-256 with ECDSA (P-256). Returns a 64-byte low-S R || S signature.
   * Biometric-gated keys prompt inside the implementation.
   */
  sign(
    alias: string,
    message: Uint8Array,
    promptTitle?: string,
  ): Promise<Uint8Array>;
  /** Refuses biometric-gated keys. Used for the ZSK, which signs many RRsets. */
  signMany(alias: string, messages: Uint8Array[]): Promise<Uint8Array[]>;
  /** Enrolment and rotation only. Zone publish does not call this. */
  attest(alias: string, challenge: Uint8Array): Promise<Attestation>;
  hardwareInfo(): Promise<HardwareInfo>;
  biometricPromptCount(): number;
}

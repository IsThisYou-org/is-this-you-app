export type HardwareTier = 'strongbox' | 'tee' | 'software';

/** ksk and zsk are used by the app. The other purposes are reserved for later authorisation. */
export type KeyPurpose = 'ksk' | 'zsk' | 'site' | 'agent' | 'log' | 'recovery';

export interface KeyRecord {
  alias: string;
  purpose: KeyPurpose;
  hardwareTier: HardwareTier;
  requireBiometric: boolean;
  spkiDerBase64: string;
  publicRawBase64: string;
  createdAt: number;
  simulator: boolean;
}

export interface Attestation {
  alias: string;
  purpose: KeyPurpose;
  challengeBase64: string;
  spkiDerBase64: string;
  hardwareTier: HardwareTier;
  simulator: boolean;
  certChainDerBase64: string[];
  attestationError?: string;
  statementJson?: string;
}

export interface GenerateKeyRequest {
  alias: string;
  purpose: KeyPurpose;
  requireBiometric: boolean;
  attestationChallenge?: Uint8Array;
  preferStrongBox?: boolean;
}

export interface HardwareInfo {
  strongBoxAvailable: boolean;
}

export interface Keystore {
  readonly kind: 'android' | 'software';
  generateKey(request: GenerateKeyRequest): Promise<KeyRecord>;
  getKey(alias: string): Promise<KeyRecord | null>;
  listKeys(): Promise<KeyRecord[]>;
  deleteKey(alias: string): Promise<void>;
  sign(alias: string, message: Uint8Array, promptTitle?: string): Promise<Uint8Array>;
  signMany(alias: string, messages: Uint8Array[]): Promise<Uint8Array[]>;
  attest(alias: string, challenge: Uint8Array): Promise<Attestation>;
  hardwareInfo(): Promise<HardwareInfo>;
  biometricPromptCount(): number;
}

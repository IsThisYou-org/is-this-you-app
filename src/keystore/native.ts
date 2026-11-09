import { decodeBase64, encodeBase64 } from '../bytes';
import { normalizeLowS } from '../crypto/p256';
import type {
  Attestation,
  GenerateKeyRequest,
  HardwareInfo,
  KeyPurpose,
  KeyRecord,
  Keystore,
} from './types';

interface NativeSignResult {
  signatureBase64: string;
  prompted: boolean;
}

interface NativeModule {
  generateKey(
    alias: string,
    purpose: string,
    requireBiometric: boolean,
    attestationChallengeBase64: string | null,
    preferStrongBox: boolean,
  ): Promise<KeyRecord>;
  getKey(alias: string): Promise<KeyRecord | null>;
  listKeys(): Promise<KeyRecord[]>;
  deleteKey(alias: string): Promise<void>;
  sign(
    alias: string,
    messageBase64: string,
    promptTitle: string,
  ): Promise<NativeSignResult>;
  signMany(alias: string, messagesBase64: string[]): Promise<string[]>;
  attest(alias: string, challengeBase64: string): Promise<Attestation>;
  hardwareInfo(): Promise<HardwareInfo>;
}

function asRecord(value: KeyRecord): KeyRecord {
  return {
    alias: value.alias,
    purpose: value.purpose as KeyPurpose,
    hardwareTier: value.hardwareTier,
    requireBiometric: Boolean(value.requireBiometric),
    spkiDerBase64: value.spkiDerBase64,
    publicRawBase64: value.publicRawBase64,
    createdAt: Number(value.createdAt),
    simulator: false,
  };
}

/** Bridge to the Kotlin Android Keystore module. */
export class NativeKeystore implements Keystore {
  readonly kind = 'android' as const;
  private prompts = 0;

  constructor(private native: NativeModule) {}

  biometricPromptCount(): number {
    return this.prompts;
  }

  async hardwareInfo(): Promise<HardwareInfo> {
    const info = await this.native.hardwareInfo();
    return { strongBoxAvailable: Boolean(info.strongBoxAvailable) };
  }

  async generateKey(request: GenerateKeyRequest): Promise<KeyRecord> {
    const record = await this.native.generateKey(
      request.alias,
      request.purpose,
      request.requireBiometric,
      request.attestationChallenge
        ? encodeBase64(request.attestationChallenge)
        : null,
      request.preferStrongBox !== false,
    );
    return asRecord(record);
  }

  async getKey(alias: string): Promise<KeyRecord | null> {
    const record = await this.native.getKey(alias);
    return record ? asRecord(record) : null;
  }

  async listKeys(): Promise<KeyRecord[]> {
    const list = await this.native.listKeys();
    return list.map(asRecord);
  }

  async deleteKey(alias: string): Promise<void> {
    await this.native.deleteKey(alias);
  }

  async sign(
    alias: string,
    message: Uint8Array,
    promptTitle?: string,
  ): Promise<Uint8Array> {
    const result = await this.native.sign(
      alias,
      encodeBase64(message),
      promptTitle ?? 'Approve key use',
    );
    if (result.prompted) {
      this.prompts += 1;
    }
    return normalizeLowS(decodeBase64(result.signatureBase64));
  }

  async signMany(alias: string, messages: Uint8Array[]): Promise<Uint8Array[]> {
    const encoded = await this.native.signMany(
      alias,
      messages.map(message => encodeBase64(message)),
    );
    return encoded.map(item => normalizeLowS(decodeBase64(item)));
  }

  async attest(alias: string, challenge: Uint8Array): Promise<Attestation> {
    return this.native.attest(alias, encodeBase64(challenge));
  }
}

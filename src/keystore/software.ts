import { decodeBase64, encodeBase64 } from '../bytes';
import {
  fingerprintSpki,
  publicRawFromPrivate,
  randomPrivateKey,
  signP256,
  spkiFromPublicRaw,
} from '../crypto/p256';
import type {
  Attestation,
  GenerateKeyRequest,
  HardwareInfo,
  KeyRecord,
  Keystore,
} from './types';

interface StoredKey {
  record: KeyRecord;
  privateKey: Uint8Array;
  challenge: Uint8Array | null;
}

/**
 * In-process P-256 keys for unit tests and for opening the UI outside Android.
 * Biometric gating is simulated: a gated sign increments the prompt counter and
 * can be set to fail. These keys are exportable. The phone build does not use
 * this class for zone keys.
 */
export class SoftwareKeystore implements Keystore {
  readonly kind = 'software' as const;
  private keys = new Map<string, StoredKey>();
  private prompts = 0;
  private biometricAllows = true;
  private attestations = 0;

  biometricPromptCount(): number {
    return this.prompts;
  }

  attestationCount(): number {
    return this.attestations;
  }

  setBiometricAllows(allows: boolean): void {
    this.biometricAllows = allows;
  }

  async hardwareInfo(): Promise<HardwareInfo> {
    return { strongBoxAvailable: false };
  }

  async generateKey(request: GenerateKeyRequest): Promise<KeyRecord> {
    if (this.keys.has(request.alias)) {
      throw new Error(`Key already exists: ${request.alias}`);
    }
    const privateKey = randomPrivateKey();
    const publicRaw = publicRawFromPrivate(privateKey);
    const spki = spkiFromPublicRaw(publicRaw);
    const record: KeyRecord = {
      alias: request.alias,
      purpose: request.purpose,
      hardwareTier: 'software',
      requireBiometric: request.requireBiometric,
      spkiDerBase64: encodeBase64(spki),
      publicRawBase64: encodeBase64(publicRaw),
      createdAt: Date.now(),
      simulator: true,
    };
    this.keys.set(request.alias, {
      record,
      privateKey,
      challenge: request.attestationChallenge ?? null,
    });
    if (request.attestationChallenge) {
      this.attestations += 1;
    }
    return record;
  }

  async getKey(alias: string): Promise<KeyRecord | null> {
    return this.keys.get(alias)?.record ?? null;
  }

  async listKeys(): Promise<KeyRecord[]> {
    return [...this.keys.values()].map(k => k.record);
  }

  async deleteKey(alias: string): Promise<void> {
    this.keys.delete(alias);
  }

  async sign(
    alias: string,
    message: Uint8Array,
    _promptTitle?: string,
  ): Promise<Uint8Array> {
    const key = this.require(alias);
    if (key.record.requireBiometric) {
      this.prompts += 1;
      if (!this.biometricAllows) {
        throw new Error('BIOMETRIC_FAILED');
      }
    }
    return signP256(message, key.privateKey);
  }

  async signMany(alias: string, messages: Uint8Array[]): Promise<Uint8Array[]> {
    const key = this.require(alias);
    if (key.record.requireBiometric) {
      throw new Error('BIOMETRIC_BATCH_REFUSED');
    }
    return messages.map(message => signP256(message, key.privateKey));
  }

  async attest(alias: string, challenge: Uint8Array): Promise<Attestation> {
    const key = this.require(alias);
    this.attestations += 1;
    const statement = {
      v: 'simulator-attestation/v1',
      alias,
      purpose: key.record.purpose,
      challengeBase64: encodeBase64(challenge),
      spkiDerBase64: key.record.spkiDerBase64,
      hardwareTier: 'software',
      note: 'Software simulator attestation. Not an Android Key Attestation certificate chain.',
    };
    return {
      alias,
      purpose: key.record.purpose,
      challengeBase64: encodeBase64(challenge),
      spkiDerBase64: key.record.spkiDerBase64,
      hardwareTier: 'software',
      simulator: true,
      certChainDerBase64: [],
      statementJson: JSON.stringify(statement),
    };
  }

  private require(alias: string): StoredKey {
    const key = this.keys.get(alias);
    if (!key) {
      throw new Error(`KEY_NOT_FOUND ${alias}`);
    }
    return key;
  }

  /** Test helper: the private scalar, so tests can show keys are not derived from each other. */
  privateScalar(alias: string): Uint8Array {
    return this.require(alias).privateKey.slice();
  }
}

export function publicRawFromRecord(record: KeyRecord): Uint8Array {
  const raw = decodeBase64(record.publicRawBase64);
  if (raw.length !== 64) {
    throw new Error(`Bad public key for ${record.alias}`);
  }
  return raw;
}

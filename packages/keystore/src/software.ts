import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha2';

import type {
  Attestation,
  GenerateKeyRequest,
  HardwareInfo,
  KeyRecord,
  Keystore,
} from './types';

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function b64(data: Uint8Array): string {
  let out = '';
  for (let i = 0; i < data.length; i += 3) {
    const a = data[i];
    const b = i + 1 < data.length ? data[i + 1] : 0;
    const c = i + 2 < data.length ? data[i + 2] : 0;
    const n = (a << 16) | (b << 8) | c;
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
    out += i + 1 < data.length ? B64[(n >> 6) & 63] : '=';
    out += i + 2 < data.length ? B64[n & 63] : '=';
  }
  return out;
}

function rawFromPrivate(privateKey: Uint8Array): Uint8Array {
  const point = p256.getPublicKey(privateKey, false);
  return point.slice(1);
}

function spki(raw: Uint8Array): Uint8Array {
  const prefix = Uint8Array.from([
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
  ]);
  const out = new Uint8Array(prefix.length + raw.length);
  out.set(prefix, 0);
  out.set(raw, prefix.length);
  return out;
}

function signMessage(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return p256.sign(sha256(message), privateKey, { lowS: true }).toCompactRawBytes();
}

interface Stored {
  record: KeyRecord;
  privateKey: Uint8Array;
}

/**
 * Exportable P-256 keys for tests and for machines with no Android Keystore.
 * A biometric-gated sign increments the prompt counter. The phone build does
 * not use this class for zone keys.
 */
export class SoftwareKeystore implements Keystore {
  readonly kind = 'software' as const;
  private keys = new Map<string, Stored>();
  private prompts = 0;
  private allow = true;
  private attestations = 0;

  biometricPromptCount(): number {
    return this.prompts;
  }

  attestationCount(): number {
    return this.attestations;
  }

  setBiometricAllows(allows: boolean): void {
    this.allow = allows;
  }

  async hardwareInfo(): Promise<HardwareInfo> {
    return { strongBoxAvailable: false };
  }

  async generateKey(request: GenerateKeyRequest): Promise<KeyRecord> {
    if (this.keys.has(request.alias)) {
      throw new Error(`Key already exists: ${request.alias}`);
    }
    const privateKey = p256.utils.randomPrivateKey();
    const raw = rawFromPrivate(privateKey);
    const record: KeyRecord = {
      alias: request.alias,
      purpose: request.purpose,
      hardwareTier: 'software',
      requireBiometric: request.requireBiometric,
      spkiDerBase64: b64(spki(raw)),
      publicRawBase64: b64(raw),
      createdAt: Date.now(),
      simulator: true,
    };
    this.keys.set(request.alias, { record, privateKey });
    if (request.attestationChallenge) {
      this.attestations += 1;
    }
    return record;
  }

  async getKey(alias: string): Promise<KeyRecord | null> {
    return this.keys.get(alias)?.record ?? null;
  }

  async listKeys(): Promise<KeyRecord[]> {
    return [...this.keys.values()].map(item => item.record);
  }

  async deleteKey(alias: string): Promise<void> {
    this.keys.delete(alias);
  }

  async sign(alias: string, message: Uint8Array): Promise<Uint8Array> {
    const key = this.require(alias);
    if (key.record.requireBiometric) {
      this.prompts += 1;
      if (!this.allow) {
        throw new Error('BIOMETRIC_FAILED');
      }
    }
    return signMessage(message, key.privateKey);
  }

  async signMany(alias: string, messages: Uint8Array[]): Promise<Uint8Array[]> {
    const key = this.require(alias);
    if (key.record.requireBiometric) {
      throw new Error('BIOMETRIC_BATCH_REFUSED');
    }
    return messages.map(message => signMessage(message, key.privateKey));
  }

  async attest(alias: string, challenge: Uint8Array): Promise<Attestation> {
    const key = this.require(alias);
    this.attestations += 1;
    return {
      alias,
      purpose: key.record.purpose,
      challengeBase64: b64(challenge),
      spkiDerBase64: key.record.spkiDerBase64,
      hardwareTier: 'software',
      simulator: true,
      certChainDerBase64: [],
      statementJson: JSON.stringify({
        v: 'simulator-attestation/v1',
        alias,
        note: 'Not an Android Key Attestation certificate chain.',
      }),
    };
  }

  private require(alias: string): Stored {
    const key = this.keys.get(alias);
    if (!key) {
      throw new Error(`KEY_NOT_FOUND ${alias}`);
    }
    return key;
  }
}

export function publicRaw(record: KeyRecord): Uint8Array {
  const clean = record.publicRawBase64.replace(/\s+/g, '');
  const out: number[] = [];
  for (let i = 0; i < clean.length; i += 4) {
    const n =
      (B64.indexOf(clean[i]) << 18) |
      (B64.indexOf(clean[i + 1]) << 12) |
      ((clean[i + 2] === '=' ? 0 : B64.indexOf(clean[i + 2])) << 6) |
      (clean[i + 3] === '=' ? 0 : B64.indexOf(clean[i + 3]));
    out.push((n >> 16) & 255);
    if (clean[i + 2] !== '=') {
      out.push((n >> 8) & 255);
    }
    if (clean[i + 3] !== '=') {
      out.push(n & 255);
    }
  }
  const raw = Uint8Array.from(out);
  if (raw.length !== 64) {
    throw new Error('bad public key');
  }
  return raw;
}

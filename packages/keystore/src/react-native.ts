import { NativeModules, Platform } from 'react-native';

import { SoftwareKeystore } from './software';
import type { Attestation, HardwareInfo, KeyRecord, Keystore } from './types';

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function encode(data: Uint8Array): string {
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

function decode(value: string): Uint8Array {
  const clean = value.replace(/\s+/g, '');
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
  return Uint8Array.from(out);
}

interface NativeSign {
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
  sign(alias: string, messageBase64: string, promptTitle: string): Promise<NativeSign>;
  signMany(alias: string, messagesBase64: string[]): Promise<string[]>;
  attest(alias: string, challengeBase64: string): Promise<Attestation>;
  hardwareInfo(): Promise<HardwareInfo>;
}

/** Bridge to the Kotlin module. BiometricPrompt runs inside sign() for the KSK. */
export class NativeKeystore implements Keystore {
  readonly kind = 'android' as const;
  private prompts = 0;

  constructor(private native: NativeModule) {}

  biometricPromptCount(): number {
    return this.prompts;
  }

  hardwareInfo(): Promise<HardwareInfo> {
    return this.native.hardwareInfo();
  }

  async generateKey(request: {
    alias: string;
    purpose: KeyRecord['purpose'];
    requireBiometric: boolean;
    attestationChallenge?: Uint8Array;
    preferStrongBox?: boolean;
  }): Promise<KeyRecord> {
    const record = await this.native.generateKey(
      request.alias,
      request.purpose,
      request.requireBiometric,
      request.attestationChallenge ? encode(request.attestationChallenge) : null,
      request.preferStrongBox !== false,
    );
    return { ...record, simulator: false };
  }

  getKey(alias: string): Promise<KeyRecord | null> {
    return this.native.getKey(alias);
  }

  listKeys(): Promise<KeyRecord[]> {
    return this.native.listKeys();
  }

  deleteKey(alias: string): Promise<void> {
    return this.native.deleteKey(alias);
  }

  async sign(alias: string, message: Uint8Array, promptTitle?: string): Promise<Uint8Array> {
    const result = await this.native.sign(alias, encode(message), promptTitle ?? 'Approve key use');
    if (result.prompted) {
      this.prompts += 1;
    }
    return decode(result.signatureBase64);
  }

  async signMany(alias: string, messages: Uint8Array[]): Promise<Uint8Array[]> {
    const signed = await this.native.signMany(alias, messages.map(encode));
    return signed.map(decode);
  }

  attest(alias: string, challenge: Uint8Array): Promise<Attestation> {
    return this.native.attest(alias, encode(challenge));
  }
}

/**
 * On Android this requires the native module. A missing module is a broken
 * build, not a reason to sign zones with an exportable software key.
 * Jest and other non-Android runs get the software keystore so the UI can render.
 */
export function createAppKeystore(): Keystore {
  if (Platform.OS === 'android') {
    const native = NativeModules.IsThisYouKeystore as NativeModule | undefined;
    if (native && typeof native.generateKey === 'function') {
      return new NativeKeystore(native);
    }
    throw new Error('The Android Keystore module is not in this build.');
  }
  return new SoftwareKeystore();
}

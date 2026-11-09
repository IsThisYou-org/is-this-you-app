import { NativeModules, Platform } from 'react-native';

import { NativeKeystore } from './native';
import { SoftwareKeystore } from './software';
import type { Keystore } from './types';

export type { Keystore, KeyRecord, HardwareTier, KeyPurpose } from './types';
export { SoftwareKeystore } from './software';
export { NativeKeystore } from './native';

/**
 * On Android the hardware module is required. A missing module is a broken
 * build, not a cue to sign zones with an exportable software key.
 * Jest and other non-Android runtimes get the software keystore so the UI
 * shell can render. Zone tests construct SoftwareKeystore themselves.
 */
export function createAppKeystore(): Keystore {
  const native = NativeModules.IsThisYouKeystore as
    | ConstructorParameters<typeof NativeKeystore>[0]
    | undefined;
  if (native && typeof native.generateKey === 'function') {
    return new NativeKeystore(native);
  }
  if (Platform.OS === 'android') {
    throw new Error(
      'The Android Keystore module is not in this build, so zone keys cannot be created.',
    );
  }
  return new SoftwareKeystore();
}

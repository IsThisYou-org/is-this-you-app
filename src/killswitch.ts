export interface KillSwitchCopy {
  effect: string;
  steps: string[];
  warnings: string[];
}

export function killSwitchCopy(apex: string, ds: string): KillSwitchCopy {
  return {
    effect:
      'The cryptographic kill switch is withdrawing the DS at the parent. After the registry publishes that change, validators that ask the parent see no secure delegation. Deleting keys on this phone does not do that.',
    steps: [
      `Sign in at the registrar for ${apex}.`,
      'Open the DNSSEC / DS records for the domain.',
      `Remove the DS that matches this phone's KSK: ${ds}`,
      'Save the change. Do this at the registrar. Uploading an empty zone is not a substitute, including for sites that pinned a key.',
    ],
    warnings: [
      'Publication is not instant. Registries often take minutes, and some take hours.',
      'Resolver caches can keep the old DS after the parent has withdrawn it.',
      'A best-effort lookup below is not an authenticated proof from the parent.',
    ],
  };
}

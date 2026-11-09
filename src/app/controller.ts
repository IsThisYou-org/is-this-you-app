import { sha256 } from '@noble/hashes/sha2';
import {
  dsFromDnskey,
  nextSoaSerial,
  paypalIdentifierError,
  publishUri,
  signZone,
  type EditableUri,
  type SigningKey,
  type WalletFields,
  type ZoneDocument,
} from '@isthisyou/dnssec-zone';
import { publicRaw, type KeyRecord, type Keystore } from '@isthisyou/keystore';

import { cloneSettings, defaultSettings, type DomainSettings } from '../config';
import { HostError, uploadZone } from '../host/client';

export interface Kv {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
}

export interface WalletDraft {
  id: string;
  type: string;
  identifier: string;
  description: string;
  sort: string;
  useEmail: boolean;
}

export interface DomainState {
  apex: string;
  createdAt: number;
  settings: DomainSettings;
  keyGeneration: number;
  ksk: KeyRecord | null;
  zsk: KeyRecord | null;
  uris: EditableUri[];
  wallets: WalletDraft[];
  registrarDsPublished: boolean;
  registrarNsPublished: boolean;
  killSwitch: 'inactive' | 'pending' | 'user_confirmed';
  lastZone: ZoneDocument | null;
  lastUpload: { serial: number; at: number } | null;
  lastSignedAt: number | null;
  lastDnskeySignedAt: number | null;
  dnskeySignatures: string[] | null;
  signatureTimes: { dnskeyExpiry: number; earliestZskExpiry: number } | null;
  lastError: { code: string; message: string } | null;
}

interface Persisted {
  version: 1;
  defaults: DomainSettings;
  domains: DomainState[];
}

export interface ChecklistItem {
  id: string;
  label: string;
  done: boolean;
  detail?: string;
}

export interface Warning {
  level: 'info' | 'warn' | 'critical';
  message: string;
}

const STATE_KEY = 'isthisyou.state.v1';

export class AppController {
  private state: Persisted = { version: 1, defaults: defaultSettings(), domains: [] };
  private clock: () => number;

  constructor(
    private keystore: Keystore,
    private kv: Kv,
    private fetchImpl?: typeof globalThis.fetch,
    now?: () => number,
  ) {
    this.clock = now ?? (() => Math.floor(Date.now() / 1000));
  }

  async load(): Promise<void> {
    const raw = await this.kv.getItem(STATE_KEY);
    if (!raw) {
      return;
    }
    const parsed = JSON.parse(raw) as Persisted;
    if (parsed?.version === 1 && Array.isArray(parsed.domains)) {
      this.state = parsed;
    }
  }

  getDefaults(): DomainSettings {
    return cloneSettings(this.state.defaults);
  }

  setDefaults(settings: DomainSettings): void {
    this.state.defaults = cloneSettings(settings);
  }

  listDomains(): DomainState[] {
    return this.state.domains.map(cloneDomain);
  }

  getDomain(apex: string): DomainState {
    return cloneDomain(this.require(apex));
  }

  async addDomain(apexInput: string, settings?: Partial<DomainSettings>): Promise<void> {
    const apex = normaliseApex(apexInput);
    if (this.state.domains.some(domain => domain.apex === apex)) {
      throw new Error(`${apex} is already on this phone`);
    }
    const domain: DomainState = {
      apex,
      createdAt: this.clock(),
      settings: { ...cloneSettings(this.state.defaults), ...settings, serviceNs: settings?.serviceNs ?? [...this.state.defaults.serviceNs] },
      keyGeneration: 1,
      ksk: null,
      zsk: null,
      uris: [],
      wallets: [],
      registrarDsPublished: false,
      registrarNsPublished: false,
      killSwitch: 'inactive',
      lastZone: null,
      lastUpload: null,
      lastSignedAt: null,
      lastDnskeySignedAt: null,
      dnskeySignatures: null,
      signatureTimes: null,
      lastError: null,
    };
    this.state.domains.push(domain);
    await this.save();
  }

  async removeDomain(apex: string): Promise<void> {
    const domain = this.require(apex);
    if (domain.ksk) {
      await this.keystore.deleteKey(domain.ksk.alias);
    }
    if (domain.zsk) {
      await this.keystore.deleteKey(domain.zsk.alias);
    }
    this.state.domains = this.state.domains.filter(item => item.apex !== domain.apex);
    await this.save();
  }

  async generateKeys(apex: string): Promise<void> {
    const domain = this.require(apex);
    if (domain.ksk || domain.zsk) {
      throw new Error('Keys already exist. Roll them if you need a new DS.');
    }
    domain.ksk = await this.keystore.generateKey({
      alias: aliasFor(apex, 'ksk', domain.keyGeneration),
      purpose: 'ksk',
      requireBiometric: true,
      preferStrongBox: true,
    });
    domain.zsk = await this.keystore.generateKey({
      alias: aliasFor(apex, 'zsk', domain.keyGeneration),
      purpose: 'zsk',
      requireBiometric: false,
      preferStrongBox: true,
    });
    await this.save();
  }

  async rollKeys(apex: string): Promise<void> {
    const domain = this.require(apex);
    if (domain.ksk) {
      await this.keystore.deleteKey(domain.ksk.alias);
    }
    if (domain.zsk) {
      await this.keystore.deleteKey(domain.zsk.alias);
    }
    domain.keyGeneration += 1;
    domain.ksk = null;
    domain.zsk = null;
    domain.dnskeySignatures = null;
    domain.signatureTimes = null;
    domain.registrarDsPublished = false;
    await this.generateKeys(apex);
  }

  updateRecords(apex: string, uris: EditableUri[], wallets: WalletDraft[]): void {
    const domain = this.require(apex);
    const defaults = uris.filter(uri => uri.isDefault);
    if (defaults.length > 1) {
      throw new Error('A zone can nominate only one default URI');
    }
    for (const wallet of wallets) {
      if (wallet.type.trim().toLowerCase() === 'paypal') {
        const error = paypalIdentifierError(wallet.identifier, wallet.useEmail);
        if (error) {
          throw new Error(error);
        }
      }
    }
    domain.uris = uris;
    domain.wallets = wallets;
  }

  async saveRecords(apex: string, uris: EditableUri[], wallets: WalletDraft[]): Promise<void> {
    this.updateRecords(apex, uris, wallets);
    await this.save();
  }

  setRegistrar(apex: string, flags: { ds?: boolean; ns?: boolean }): void {
    const domain = this.require(apex);
    if (flags.ds != null) {
      domain.registrarDsPublished = flags.ds;
    }
    if (flags.ns != null) {
      domain.registrarNsPublished = flags.ns;
    }
    void this.save();
  }

  async setKillSwitch(apex: string, status: DomainState['killSwitch']): Promise<void> {
    this.require(apex).killSwitch = status;
    await this.save();
  }

  async signAndUpload(
    apex: string,
    options: { resignDnskey?: boolean } = {},
  ): Promise<{ serial: number }> {
    const domain = this.require(apex);
    if (!domain.ksk || !domain.zsk) {
      throw new Error('Generate the KSK and ZSK first');
    }
    const resignDnskey = options.resignDnskey ?? !domain.dnskeySignatures;
    const build = async (serial: number, now: number, resign: boolean) => {
      const signed = await this.sign(domain, serial, now, resign);
      if (resign) {
        domain.dnskeySignatures = signed.dnskeySignatureRrdatas;
        domain.lastDnskeySignedAt = now;
      }
      domain.signatureTimes = {
        dnskeyExpiry: signed.dnskeyExpiry,
        earliestZskExpiry: signed.earliestZskExpiry,
      };
      return signed.document;
    };
    const now = this.clock();
    let serial = nextSoaSerial({
      now,
      lastAccepted: domain.lastUpload?.serial ?? null,
      maxAheadSeconds: domain.settings.freshnessMaxAheadSeconds,
      maxBehindSeconds: domain.settings.freshnessMaxBehindSeconds,
    });
    let document = await build(serial, now, resignDnskey);
    try {
      const uploaded = await uploadZone({
        baseUrl: domain.settings.uploadBaseUrl,
        document,
        fetchImpl: this.fetchImpl as never,
        resign: async info => {
          const later = this.clock();
          const floor = Math.max(domain.lastUpload?.serial ?? 0, info.storedSerial ?? 0);
          serial = nextSoaSerial({
            now: later,
            lastAccepted: floor > 0 ? floor : null,
            maxAheadSeconds: domain.settings.freshnessMaxAheadSeconds,
            maxBehindSeconds: domain.settings.freshnessMaxBehindSeconds,
          });
          document = await build(serial, later, false);
          return document;
        },
      });
      domain.lastZone = uploaded.document;
      domain.lastUpload = { serial: uploaded.serial, at: this.clock() };
      domain.lastSignedAt = this.clock();
      domain.lastError = null;
      await this.save();
      return { serial: uploaded.serial };
    } catch (error) {
      domain.lastError = {
        code: error instanceof HostError ? error.code : 'upload_failed',
        message: error instanceof Error ? error.message : 'upload failed',
      };
      await this.save();
      throw error;
    }
  }

  async resignDueDomains(): Promise<string[]> {
    const done: string[] = [];
    for (const domain of [...this.state.domains]) {
      if (!this.isResignDue(domain.apex)) {
        continue;
      }
      await this.signAndUpload(domain.apex, { resignDnskey: false });
      done.push(domain.apex);
    }
    return done;
  }

  isResignDue(apex: string): boolean {
    const domain = this.require(apex);
    if (!domain.ksk || !domain.zsk || !domain.dnskeySignatures || !domain.lastSignedAt) {
      return false;
    }
    const now = this.clock();
    if (now - domain.lastSignedAt >= domain.settings.resignIntervalSeconds) {
      return true;
    }
    if (
      domain.signatureTimes &&
      domain.signatureTimes.earliestZskExpiry - now <= domain.settings.rrsigWarnSeconds
    ) {
      return true;
    }
    return false;
  }

  warnings(apex: string): Warning[] {
    const domain = this.require(apex);
    const now = this.clock();
    const out: Warning[] = [];
    if (!domain.ksk || !domain.zsk) {
      out.push({ level: 'info', message: 'Zone keys have not been generated yet.' });
      return out;
    }
    const tier = domain.ksk.hardwareTier;
    out.push({
      level: tier === 'software' ? 'warn' : 'info',
      message: `KSK is ${tier}${domain.ksk.requireBiometric ? ', biometric required' : ''}. ZSK is ${domain.zsk.hardwareTier}.`,
    });
    if (!domain.lastUpload) {
      out.push({ level: 'info', message: 'The hosting service has not accepted this zone yet.' });
    }
    if (domain.signatureTimes) {
      const left = domain.signatureTimes.earliestZskExpiry - now;
      if (left <= domain.settings.rrsigCriticalSeconds) {
        out.push({ level: 'critical', message: 'Zone signatures expire very soon. Re-sign and upload.' });
      } else if (left <= domain.settings.rrsigWarnSeconds) {
        out.push({ level: 'warn', message: 'Zone signatures are approaching expiry.' });
      }
      const kskLeft = domain.signatureTimes.dnskeyExpiry - now;
      if (kskLeft <= domain.settings.rrsigWarnSeconds) {
        out.push({
          level: kskLeft <= domain.settings.rrsigCriticalSeconds ? 'critical' : 'warn',
          message: 'The DNSKEY signature needs the KSK again before it expires.',
        });
      }
    }
    if (domain.lastSignedAt && now - domain.lastSignedAt >= domain.settings.resignOverdueSeconds) {
      out.push({ level: 'warn', message: 'The weekly re-sign is overdue.' });
    }
    if (domain.killSwitch === 'pending') {
      out.push({ level: 'warn', message: 'DS withdrawal is marked pending. Publication is not instant.' });
    }
    return out;
  }

  checklist(apex: string): ChecklistItem[] {
    const domain = this.require(apex);
    const uploaded = Boolean(domain.lastUpload);
    return [
      { id: 'keys', label: 'Generate a KSK and a ZSK on this phone', done: Boolean(domain.ksk && domain.zsk) },
      { id: 'zone', label: 'Build a signed zone', done: Boolean(domain.lastSignedAt) },
      {
        id: 'registrar',
        label: 'At the registrar, publish the DS and set NS to every hosting nameserver',
        done: domain.registrarDsPublished && domain.registrarNsPublished,
      },
      {
        id: 'upload',
        label: uploaded ? 'Hosting service accepted the zone' : 'Upload the signed zone',
        done: uploaded,
        detail: uploaded
          ? 'The host accepted the zone. Resolvers may still SERVFAIL until secondaries finish AXFR.'
          : 'The app does not call the zone live until an upload is accepted.',
      },
    ];
  }

  dsPresentation(apex: string): string {
    const domain = this.require(apex);
    if (!domain.ksk) {
      return '';
    }
    const rdata = dnskeyRdata(257, publicRaw(domain.ksk));
    const ds = dsFromDnskey(apex, rdata, 2);
    return `${apex}. IN DS ${ds.keyTag} 13 2 ${toHex(ds.digest)}`;
  }

  private async sign(domain: DomainState, serial: number, now: number, resignDnskey: boolean) {
    const ksk = domain.ksk;
    const zsk = domain.zsk;
    if (!ksk || !zsk) {
      throw new Error('keys missing');
    }
    const toKey = (record: KeyRecord): SigningKey => ({
      publicRaw: publicRaw(record),
      sign: message => this.keystore.sign(record.alias, message, 'Sign the DNSKEY set'),
      signMany: messages => this.keystore.signMany(record.alias, messages),
    });
    return signZone({
      apex: domain.apex,
      serial,
      now,
      mname: domain.settings.mname,
      rname: `${domain.settings.rnameLocalPart}.${domain.apex}`,
      ns: domain.settings.serviceNs,
      ttl: domain.settings.ttl,
      soa: {
        refresh: domain.settings.soaRefresh,
        retry: domain.settings.soaRetry,
        expire: domain.settings.soaExpire,
        minimum: domain.settings.soaMinimum,
      },
      txt: [],
      uri: domain.uris.map(publishUri),
      wallet: domain.wallets.map(toWallet),
      ksk: toKey(ksk),
      zsk: toKey(zsk),
      resignDnskey,
      existingDnskeySignatures: resignDnskey ? undefined : domain.dnskeySignatures ?? undefined,
      nsecMode: domain.settings.nsecMode,
      nsec3: {
        iterations: domain.settings.nsec3Iterations,
        salt: hexOrEmpty(domain.settings.nsec3SaltHex),
        optOut: domain.settings.nsec3OptOut,
      },
      validitySeconds: domain.settings.rrsigValiditySeconds,
      inceptionBackdateSeconds: domain.settings.inceptionBackdateSeconds,
      jitterMaxSeconds: domain.settings.jitterMaxSeconds,
    });
  }

  private require(apex: string): DomainState {
    const found = this.state.domains.find(domain => domain.apex === normaliseApex(apex));
    if (!found) {
      throw new Error(`Unknown domain ${apex}`);
    }
    return found;
  }

  private async save(): Promise<void> {
    await this.kv.setItem(STATE_KEY, JSON.stringify(this.state));
  }
}

function toWallet(draft: WalletDraft): WalletFields {
  const sort = draft.sort.trim();
  return {
    type: draft.type,
    identifier: draft.identifier,
    description: draft.description.trim() || undefined,
    sort: /^-?\d+$/.test(sort) ? Number(sort) : null,
  };
}

function aliasFor(apex: string, purpose: 'ksk' | 'zsk', generation: number): string {
  const bytes = Uint8Array.from(apex, char => char.charCodeAt(0));
  const digest = sha256(bytes);
  let hex = '';
  for (const b of digest) {
    hex += b.toString(16).padStart(2, '0');
  }
  return `ity-${purpose}-${hex.slice(0, 12)}-${generation}`;
}

function normaliseApex(value: string): string {
  const apex = value.trim().toLowerCase().replace(/\.$/, '');
  if (!apex || apex.includes('..')) {
    throw new Error('Enter a domain name');
  }
  return apex;
}

function cloneDomain(domain: DomainState): DomainState {
  return JSON.parse(JSON.stringify(domain)) as DomainState;
}

function hexOrEmpty(hex: string): Uint8Array {
  if (!hex) {
    return new Uint8Array();
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toHex(data: Uint8Array): string {
  let out = '';
  for (const b of data) {
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}

function dnskeyRdata(flags: number, raw: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + raw.length);
  out[0] = (flags >> 8) & 0xff;
  out[1] = flags & 0xff;
  out[2] = 3;
  out[3] = 13;
  out.set(raw, 4);
  return out;
}

export { STATE_KEY };

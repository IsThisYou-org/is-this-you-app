import { decodeBase64 } from './bytes';
import { typeCode } from './types';
import { presentationToRdata, type WireRr } from './wire';

export interface DohMessage {
  status: number;
  /** Present on the JSON response. Never treated as proof. */
  ad: boolean;
  answer: WireRr[];
  authority: WireRr[];
  error?: string;
  source: 'primary' | 'fallback';
}

export interface DohClient {
  query(name: string, type: string): Promise<DohMessage>;
}

export interface FetchLike {
  (url: string, init?: { headers?: Record<string, string> }): Promise<{
    ok: boolean;
    status: number;
    json: () => Promise<unknown>;
  }>;
}

export const DEFAULT_DOH_URL = 'https://api.web3dns.net/';
/** Used only when the primary resolver rejects a name it cannot spell, such as the root. */
export const DEFAULT_DOH_FALLBACK_URL = 'https://dns.google/resolve';

interface RawRr {
  name?: string;
  type?: number;
  TTL?: number;
  ttl?: number;
  data?: string;
  rdata?: string;
  typename?: string;
}

export function createDohClient(options: {
  baseUrl?: string;
  fallbackUrl?: string | null;
  fetchImpl?: FetchLike;
}): DohClient {
  const baseUrl = options.baseUrl ?? DEFAULT_DOH_URL;
  const fallbackUrl =
    options.fallbackUrl === undefined ? DEFAULT_DOH_FALLBACK_URL : options.fallbackUrl;
  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as FetchLike);
  return {
    async query(name: string, type: string): Promise<DohMessage> {
      const primary = await request(fetchImpl, baseUrl, name, type);
      if (!primary.error || !fallbackUrl) {
        return { ...primary, source: 'primary' };
      }
      if (!/not a valid fqdn/i.test(primary.error)) {
        return { ...primary, source: 'primary' };
      }
      const fallback = await request(fetchImpl, fallbackUrl, name, type);
      return { ...fallback, source: 'fallback' };
    },
  };
}

async function request(
  fetchImpl: FetchLike,
  baseUrl: string,
  name: string,
  type: string,
): Promise<Omit<DohMessage, 'source'>> {
  const url = new URL(baseUrl);
  url.searchParams.set('name', name);
  url.searchParams.set('type', type);
  url.searchParams.set('do', '1');
  try {
    const response = await fetchImpl(url.toString(), {
      headers: { Accept: 'application/dns-json' },
    });
    const body = (await response.json()) as {
      error?: string;
      Status?: number;
      AD?: boolean;
      Answer?: RawRr[];
      Authority?: RawRr[];
    };
    if (!response.ok || body.error) {
      return {
        status: body.Status ?? response.status,
        ad: false,
        answer: [],
        authority: [],
        error: body.error || `HTTP ${response.status}`,
      };
    }
    return {
      status: body.Status ?? 0,
      ad: Boolean(body.AD),
      answer: (body.Answer ?? []).map(toWire),
      authority: (body.Authority ?? []).map(toWire),
    };
  } catch (error) {
    return {
      status: 2,
      ad: false,
      answer: [],
      authority: [],
      error: error instanceof Error ? error.message : 'lookup failed',
    };
  }
}

function toWire(rr: RawRr): WireRr {
  const type = rr.type ?? typeCode((rr.typename ?? 'A').toUpperCase());
  const text = rr.data;
  let rdata: Uint8Array;
  if (rr.rdata) {
    rdata = decodeBase64(rr.rdata);
  } else if (text) {
    rdata = presentationToRdata(type, text);
  } else {
    rdata = new Uint8Array();
  }
  return {
    name: rr.name ?? '',
    type,
    ttl: rr.TTL ?? rr.ttl ?? 0,
    rdata,
    text,
  };
}

export type { WireRr };

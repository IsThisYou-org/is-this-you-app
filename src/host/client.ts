import type { ZoneDocument } from '@isthisyou/dnssec-zone';

export class HostError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

const RETRYABLE = new Set(['serial_stale', 'serial_in_future', 'serial_not_increased']);

const HELP: Record<string, string> = {
  parent_ds_missing: 'The parent has no DS for this domain yet. Publish the DS at the registrar, then upload again.',
  parent_ds_mismatch: 'The parent DS does not match this phone\'s KSK.',
  parent_ns_incomplete: 'The parent NS set does not include every hosting-service nameserver.',
  ns_set_mismatch: 'The parent NS set is not the same as the NS set in the zone.',
  parent_chain_invalid: 'The host could not validate the parent DNSSEC chain.',
  parent_lookup_unavailable: 'The host could not look up the parent. Try again later.',
  serial_stale: 'The SOA serial is outside the host\'s freshness window. The app re-signs and retries.',
  serial_in_future: 'The SOA serial is ahead of the host clock. The app re-signs and retries.',
  serial_not_increased: 'The SOA serial is not newer than the published one. The app re-signs and retries.',
  zone_validation_failed: 'The host rejected the zone signatures.',
  rate_limited: 'The host rate limit was hit. Wait and try again.',
  apex_ns_incomplete: 'The zone is missing its apex NS records.',
  bad_dnskey: 'The DNSKEY set was rejected.',
  bad_nsec3param: 'The NSEC3 chain was rejected.',
};

export interface FetchLike {
  (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }): Promise<{
    ok: boolean;
    status: number;
    json: () => Promise<unknown>;
    text: () => Promise<string>;
  }>;
}

export function explainHostError(code: string, message: string): string {
  return HELP[code] ? `${HELP[code]} (${message})` : message;
}

export async function uploadZone(options: {
  baseUrl: string;
  document: ZoneDocument;
  fetchImpl?: FetchLike;
  resign: (info: { code: string; storedSerial: number | null }) => Promise<ZoneDocument>;
}): Promise<{ document: ZoneDocument; serial: number; attempts: number }> {
  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as FetchLike);
  let document = options.document;
  for (let attempt = 1; attempt <= 2; attempt++) {
    const apex = document.apex.replace(/\.$/, '');
    const response = await fetchImpl(
      `${options.baseUrl.replace(/\/$/, '')}/v1/zones/${encodeURIComponent(apex)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(document),
      },
    );
    const body = await readBody(response);
    if (response.ok) {
      const serial = typeof body.serial === 'number' ? body.serial : serialOf(document);
      return { document, serial, attempts: attempt };
    }
    const code = typeof body.error === 'string' ? body.error : 'bad_request';
    const message = typeof body.message === 'string' ? body.message : `HTTP ${response.status}`;
    if (attempt === 1 && RETRYABLE.has(code)) {
      const stored = /stored serial (\d+)/.exec(message);
      document = await options.resign({
        code,
        storedSerial: stored ? Number(stored[1]) : null,
      });
      continue;
    }
    throw new HostError(code, explainHostError(code, message));
  }
  throw new HostError('upload_failed', 'upload did not succeed');
}

function serialOf(document: ZoneDocument): number {
  const soa = document.rrsets.find(rr => rr.type === 'SOA');
  const text = soa?.rrdatas[0] ?? '';
  const parts = text.trim().split(/\s+/);
  return Number(parts[2] ?? 0);
}

async function readBody(response: { json: () => Promise<unknown>; text: () => Promise<string> }): Promise<Record<string, unknown>> {
  try {
    const body = await response.json();
    return body && typeof body === 'object' ? (body as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** SOA serial is Unix time, inside the hosting service's freshness window. */
export function nextSoaSerial(opts: {
  now: number;
  serverTime?: number;
  lastAccepted: number | null;
  maxAheadSeconds: number;
  maxBehindSeconds: number;
}): number {
  const base = opts.serverTime ?? opts.now;
  let serial = base;
  if (opts.lastAccepted != null && serial <= opts.lastAccepted) {
    serial = opts.lastAccepted + 1;
  }
  if (serial > base + opts.maxAheadSeconds) {
    throw new Error(
      'SOA serial would be too far ahead of the host clock. Check the phone clock and try again.',
    );
  }
  if (serial < base - opts.maxBehindSeconds) {
    throw new Error(
      'SOA serial would be too far behind the host clock. Check the phone clock and try again.',
    );
  }
  return serial;
}

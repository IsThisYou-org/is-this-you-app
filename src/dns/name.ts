import { utf8Encode } from '../bytes';
import { Writer } from './writer';

export function normalizeDnsName(name: string): string {
  let n = name.trim().toLowerCase();
  if (n.endsWith('.')) {
    n = n.slice(0, -1);
  }
  if (!n || n.length > 253 || n.includes('..')) {
    throw new Error(`Bad DNS name: ${name}`);
  }
  for (const label of n.split('.')) {
    if (
      label.length < 1 ||
      label.length > 63 ||
      !/^[a-z0-9_-]+$/.test(label)
    ) {
      throw new Error(`Bad DNS label in ${name}`);
    }
  }
  return n;
}

export function presentName(name: string): string {
  return `${normalizeDnsName(name)}.`;
}

export function encodeName(name: string): Uint8Array {
  const n = normalizeDnsName(name);
  const w = new Writer();
  for (const label of n.split('.')) {
    const bytes = utf8Encode(label);
    w.u8(bytes.length);
    w.bytes(bytes);
  }
  w.u8(0);
  return w.concat();
}

export function labelCount(name: string): number {
  return normalizeDnsName(name).split('.').length;
}

/** Canonical DNS name order: labels compared from the right, shorter prefix first. */
export function compareNames(a: string, b: string): number {
  const la = normalizeDnsName(a).split('.').reverse();
  const lb = normalizeDnsName(b).split('.').reverse();
  const n = Math.max(la.length, lb.length);
  for (let i = 0; i < n; i++) {
    if (i >= la.length) {
      return -1;
    }
    if (i >= lb.length) {
      return 1;
    }
    if (la[i] < lb[i]) {
      return -1;
    }
    if (la[i] > lb[i]) {
      return 1;
    }
  }
  return 0;
}

export function emptyNonTerminals(names: string[], apex: string): string[] {
  const apexName = normalizeDnsName(apex);
  const apexLabels = apexName.split('.').length;
  const set = new Set(names.map(normalizeDnsName));
  const ents = new Set<string>();
  for (const name of set) {
    const labels = name.split('.');
    for (let i = 1; i <= labels.length - apexLabels - 1; i++) {
      const parent = labels.slice(i).join('.');
      if (!set.has(parent)) {
        ents.add(parent);
      }
    }
  }
  return [...ents];
}

export function sameName(a: string, b: string): boolean {
  return normalizeDnsName(a) === normalizeDnsName(b);
}

export class Writer {
  private parts: Uint8Array[] = [];

  u8(n: number): void {
    this.parts.push(Uint8Array.of(n & 0xff));
  }

  u16(n: number): void {
    this.parts.push(Uint8Array.of((n >> 8) & 0xff, n & 0xff));
  }

  u32(n: number): void {
    this.parts.push(
      Uint8Array.of(
        (n >>> 24) & 0xff,
        (n >>> 16) & 0xff,
        (n >>> 8) & 0xff,
        n & 0xff,
      ),
    );
  }

  bytes(data: Uint8Array): void {
    this.parts.push(data);
  }

  concat(): Uint8Array {
    let n = 0;
    for (const p of this.parts) {
      n += p.length;
    }
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of this.parts) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  }
}

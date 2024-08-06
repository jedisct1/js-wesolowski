import { describe, test, expect } from "bun:test";
import {
  gcd,
  modpow,
  u32be,
  u64be,
  concatBytes,
  bigintToBytes,
  bytesToBigint,
  bigintByteLength,
  bigintToFixedBytes,
} from "../src/utils.ts";

describe("gcd", () => {
  test("computes gcd of coprime numbers", () => {
    expect(gcd(17n, 13n)).toBe(1n);
    expect(gcd(100n, 37n)).toBe(1n);
  });

  test("computes gcd of numbers with common factors", () => {
    expect(gcd(12n, 8n)).toBe(4n);
    expect(gcd(100n, 75n)).toBe(25n);
    expect(gcd(48n, 18n)).toBe(6n);
  });

  test("handles zero", () => {
    expect(gcd(0n, 5n)).toBe(5n);
    expect(gcd(5n, 0n)).toBe(5n);
  });

  test("handles equal numbers", () => {
    expect(gcd(7n, 7n)).toBe(7n);
  });
});

describe("modpow", () => {
  test("computes modular exponentiation", () => {
    expect(modpow(2n, 10n, 1000n)).toBe(24n); // 2^10 = 1024 mod 1000 = 24
    expect(modpow(3n, 5n, 7n)).toBe(5n); // 3^5 = 243 mod 7 = 5
  });

  test("handles large exponents", () => {
    expect(modpow(2n, 1000n, 1000000007n)).toBe(688423210n);
  });

  test("handles zero exponent", () => {
    expect(modpow(5n, 0n, 7n)).toBe(1n);
  });

  test("handles one as exponent", () => {
    expect(modpow(5n, 1n, 7n)).toBe(5n);
  });
});

describe("u32be", () => {
  test("encodes zero", () => {
    expect(u32be(0)).toEqual(new Uint8Array([0, 0, 0, 0]));
  });

  test("encodes small number", () => {
    expect(u32be(256)).toEqual(new Uint8Array([0, 0, 1, 0]));
  });

  test("encodes max value", () => {
    expect(u32be(0xffffffff)).toEqual(new Uint8Array([255, 255, 255, 255]));
  });
});

describe("u64be", () => {
  test("encodes zero", () => {
    expect(u64be(0n)).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]));
  });

  test("encodes small number", () => {
    expect(u64be(256n)).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 1, 0]));
  });

  test("encodes large number", () => {
    expect(u64be(0x0102030405060708n)).toEqual(
      new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
    );
  });

  test("throws on negative", () => {
    expect(() => u64be(-1n)).toThrow(RangeError);
  });

  test("throws on overflow", () => {
    expect(() => u64be(0x1_0000_0000_0000_0000n)).toThrow(RangeError);
  });
});

describe("concatBytes", () => {
  test("concatenates arrays", () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4, 5]);
    expect(concatBytes(a, b)).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
  });

  test("handles empty arrays", () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([]);
    expect(concatBytes(a, b)).toEqual(new Uint8Array([1, 2]));
  });

  test("handles single array", () => {
    const a = new Uint8Array([1, 2, 3]);
    expect(concatBytes(a)).toEqual(new Uint8Array([1, 2, 3]));
  });
});

describe("bigintToBytes / bytesToBigint", () => {
  test("roundtrips zero", () => {
    const bytes = bigintToBytes(0n);
    expect(bytes).toEqual(new Uint8Array([0]));
    expect(bytesToBigint(bytes)).toBe(0n);
  });

  test("roundtrips small number", () => {
    const bytes = bigintToBytes(255n);
    expect(bytes).toEqual(new Uint8Array([255]));
    expect(bytesToBigint(bytes)).toBe(255n);
  });

  test("roundtrips large number", () => {
    const n = 0x123456789abcdef0n;
    const bytes = bigintToBytes(n);
    expect(bytesToBigint(bytes)).toBe(n);
  });

  test("pads odd hex length", () => {
    const bytes = bigintToBytes(0xfn);
    expect(bytes).toEqual(new Uint8Array([15]));
  });
});

describe("bigintByteLength", () => {
  test("returns 1 for zero", () => {
    expect(bigintByteLength(0n)).toBe(1);
  });

  test("returns 1 for small values", () => {
    expect(bigintByteLength(255n)).toBe(1);
  });

  test("returns 2 for 256", () => {
    expect(bigintByteLength(256n)).toBe(2);
  });

  test("returns correct length for large numbers", () => {
    expect(bigintByteLength(0xfffffffffffffffn)).toBe(8);
  });
});

describe("bigintToFixedBytes", () => {
  test("pads to fixed length", () => {
    expect(bigintToFixedBytes(1n, 4)).toEqual(new Uint8Array([0, 0, 0, 1]));
  });

  test("returns exact length when equal", () => {
    expect(bigintToFixedBytes(0xffn, 1)).toEqual(new Uint8Array([255]));
  });

  test("throws when too large", () => {
    expect(() => bigintToFixedBytes(256n, 1)).toThrow(RangeError);
  });
});

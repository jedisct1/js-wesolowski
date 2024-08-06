import { describe, test, expect } from "bun:test";
import { isPrime, getPrime, nextPrime } from "../src/prime.ts";

describe("isPrime", () => {
  test("returns false for numbers less than 2", () => {
    expect(isPrime(0n)).toBe(false);
    expect(isPrime(1n)).toBe(false);
    expect(isPrime(-1n)).toBe(false);
  });

  test("returns true for small primes", () => {
    expect(isPrime(2n)).toBe(true);
    expect(isPrime(3n)).toBe(true);
    expect(isPrime(5n)).toBe(true);
    expect(isPrime(7n)).toBe(true);
    expect(isPrime(11n)).toBe(true);
    expect(isPrime(13n)).toBe(true);
  });

  test("returns false for small composites", () => {
    expect(isPrime(4n)).toBe(false);
    expect(isPrime(6n)).toBe(false);
    expect(isPrime(8n)).toBe(false);
    expect(isPrime(9n)).toBe(false);
    expect(isPrime(10n)).toBe(false);
  });

  test("returns true for known primes", () => {
    expect(isPrime(997n)).toBe(true);
    expect(isPrime(7919n)).toBe(true);
    expect(isPrime(104729n)).toBe(true);
  });

  test("returns false for Carmichael numbers", () => {
    // These are composites that pass Fermat primality test
    expect(isPrime(561n)).toBe(false); // 3 × 11 × 17
    expect(isPrime(1105n)).toBe(false); // 5 × 13 × 17
    expect(isPrime(1729n)).toBe(false); // 7 × 13 × 19 (Hardy-Ramanujan number)
  });

  test("handles large primes", () => {
    // A known 256-bit prime
    const largePrime =
      115792089237316195423570985008687907853269984665640564039457584007913129639747n;
    expect(isPrime(largePrime)).toBe(true);
  });

  test("handles large composites", () => {
    // Product of two primes
    const composite =
      115792089237316195423570985008687907853269984665640564039457584007913129639747n *
      2n;
    expect(isPrime(composite)).toBe(false);
  });
});

describe("getPrime", () => {
  test("generates prime with default 256 bits", () => {
    const p = getPrime();
    expect(isPrime(p)).toBe(true);
    expect(p >= 1n << 255n).toBe(true); // High bit set
    expect(p < 1n << 256n).toBe(true);
  });

  test("generates prime with custom bit length", () => {
    const p = getPrime({ bits: 128 });
    expect(isPrime(p)).toBe(true);
    expect(p >= 1n << 127n).toBe(true);
    expect(p < 1n << 128n).toBe(true);
  });

  test("generates different primes each call", () => {
    const p1 = getPrime({ bits: 64 });
    const p2 = getPrime({ bits: 64 });
    // Very unlikely to be equal for random primes
    expect(p1).not.toBe(p2);
  });
});

describe("nextPrime", () => {
  test("returns 2 for inputs <= 2", () => {
    expect(nextPrime(0n)).toBe(2n);
    expect(nextPrime(1n)).toBe(2n);
    expect(nextPrime(2n)).toBe(2n);
  });

  test("returns same number if already prime", () => {
    expect(nextPrime(7n)).toBe(7n);
    expect(nextPrime(11n)).toBe(11n);
    expect(nextPrime(997n)).toBe(997n);
  });

  test("finds next prime for composites", () => {
    expect(nextPrime(4n)).toBe(5n);
    expect(nextPrime(6n)).toBe(7n);
    expect(nextPrime(8n)).toBe(11n);
    expect(nextPrime(9n)).toBe(11n);
    expect(nextPrime(10n)).toBe(11n);
  });

  test("handles gaps between primes", () => {
    expect(nextPrime(24n)).toBe(29n);
    expect(nextPrime(90n)).toBe(97n);
  });
});

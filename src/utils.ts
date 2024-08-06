/**
 * Compute greatest common divisor of two bigints using Euclidean algorithm.
 */
export function gcd(a: bigint, b: bigint): bigint {
  while (b !== 0n) {
    [a, b] = [b, a % b];
  }
  return a;
}

/**
 * Encode a 32-bit unsigned integer as big-endian bytes.
 */
export function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}

/**
 * Encode a 64-bit unsigned bigint as big-endian bytes.
 */
export function u64be(x: bigint): Uint8Array {
  if (x < 0n || x > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError("u64be out of range");
  }
  const b = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
}

/**
 * Concatenate multiple byte arrays into one.
 */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Convert a bigint to its minimal byte representation.
 */
export function bigintToBytes(x: bigint): Uint8Array {
  if (x === 0n) {
    return new Uint8Array([0]);
  }
  let hex = x.toString(16);
  if (hex.length % 2 === 1) hex = "0" + hex;
  return new Uint8Array(Buffer.from(hex, "hex"));
}

/**
 * Get the byte length required to represent a bigint.
 */
export function bigintByteLength(x: bigint): number {
  if (x === 0n) return 1;
  // toString(16) is highly optimized in JS engines
  return Math.ceil(x.toString(16).length / 2);
}

/**
 * Convert a bigint to a fixed-length byte array (zero-padded on the left).
 */
export function bigintToFixedBytes(x: bigint, len: number): Uint8Array {
  const bytes = bigintToBytes(x);
  if (bytes.length > len) {
    throw new RangeError("bigint too large for fixed length");
  }
  if (bytes.length === len) {
    return bytes;
  }
  const out = new Uint8Array(len);
  out.set(bytes, len - bytes.length);
  return out;
}

/**
 * Convert bytes to a bigint (big-endian).
 */
export function bytesToBigint(bytes: Uint8Array): bigint {
  if (bytes.length === 0) return 0n;
  return BigInt("0x" + Buffer.from(bytes).toString("hex"));
}

/**
 * Modular exponentiation: compute x^y mod p using square-and-multiply.
 */
export function modpow(x: bigint, y: bigint, p: bigint): bigint {
  if (y === 0n) return 1n;
  if (y === 1n) return x % p;
  if (y === 2n) return (x * x) % p;

  let res = 1n;
  x = x % p;
  while (y > 0n) {
    if (y & 1n) {
      res = (res * x) % p;
    }
    y >>= 1n; // Faster than division
    x = (x * x) % p;
  }
  return res;
}

/**
 * Montgomery form arithmetic for efficient repeated modular operations.
 * Useful when performing many multiplications with the same modulus.
 */
export class MontgomeryReducer {
  public readonly n: bigint;
  private readonly rBits: number;
  private readonly rMask: bigint;
  private readonly nPrime: bigint;
  private readonly r: bigint;

  constructor(n: bigint) {
    this.n = n;
    // Choose R as power of 2 > n
    this.rBits = n.toString(2).length;
    if ((1n << BigInt(this.rBits)) <= n) {
      this.rBits++;
    }
    this.r = 1n << BigInt(this.rBits);
    this.rMask = this.r - 1n;
    this.nPrime = this.computeNPrime();
  }

  private computeNPrime(): bigint {
    // Compute n' such that n * n' ≡ -1 (mod R)
    let nInv = 1n;
    for (let i = 0; i < this.rBits; i++) {
      nInv = (nInv * (2n - this.n * nInv)) & this.rMask;
    }
    return (this.r - nInv) & this.rMask;
  }

  /** Convert x to Montgomery form: x * R mod n */
  toMontgomery(x: bigint): bigint {
    return (x * this.r) % this.n;
  }

  /** Convert from Montgomery form: x * R^-1 mod n */
  fromMontgomery(x: bigint): bigint {
    return this.reduce(x);
  }

  /** Montgomery reduction: compute x * R^-1 mod n */
  private reduce(x: bigint): bigint {
    const m = ((x & this.rMask) * this.nPrime) & this.rMask;
    const t = (x + m * this.n) >> BigInt(this.rBits);
    return t >= this.n ? t - this.n : t;
  }

  /** Montgomery multiplication: compute a * b * R^-1 mod n (inputs/output in Montgomery form) */
  multiply(a: bigint, b: bigint): bigint {
    return this.reduce(a * b);
  }

  /** Square in Montgomery form */
  square(a: bigint): bigint {
    return this.reduce(a * a);
  }
}

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
 * Get the bit length required to represent a bigint.
 */
export function bigintBitLength(x: bigint): number {
  if (x === 0n) return 0;
  const bytes = bigintByteLength(x);
  const shift = BigInt((bytes - 1) * 8);
  const msb = Number((x >> shift) & 0xffn);
  return (bytes - 1) * 8 + (32 - Math.clz32(msb));
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

// Windowed modular exponentiation tuning.
const MODPOW_WINDOW_THRESHOLD_BITS = 64;
const MODPOW_MONTGOMERY_THRESHOLD_N_BITS = 1024;
const MODPOW_MONTGOMERY_THRESHOLD_EXP_BITS = 128;

const MODPOW_MONTGOMERY_CACHE_LIMIT = 10;
const modpowMontgomeryCache = new Map<bigint, MontgomeryReducer>();

function getMontgomeryReducerCached(n: bigint): MontgomeryReducer {
  let reducer = modpowMontgomeryCache.get(n);
  if (!reducer) {
    reducer = new MontgomeryReducer(n);
    if (modpowMontgomeryCache.size < MODPOW_MONTGOMERY_CACHE_LIMIT) {
      modpowMontgomeryCache.set(n, reducer);
    }
  }
  return reducer;
}

function shouldUseMontgomeryForModpow(n: bigint, expBits: number): boolean {
  if ((n & 1n) === 0n) return false;
  if (expBits < MODPOW_MONTGOMERY_THRESHOLD_EXP_BITS) return false;
  const nBits = bigintByteLength(n) * 8;
  return nBits >= MODPOW_MONTGOMERY_THRESHOLD_N_BITS;
}

function selectWindowSize(expBits: number): number {
  if (expBits <= 32) return 1;
  if (expBits <= 96) return 3;
  if (expBits <= 384) return 4;
  if (expBits <= 1024) return 5;
  return 6;
}

function modpowClassic(base: bigint, exp: bigint, mod: bigint): bigint {
  let res = 1n;
  let x = base;
  let y = exp;
  while (y > 0n) {
    if (y & 1n) {
      res = (res * x) % mod;
    }
    y >>= 1n;
    if (y > 0n) {
      x = (x * x) % mod;
    }
  }
  return res;
}

function modpowWindowedCore(
  base: bigint,
  bits: string,
  window: number,
  square: (x: bigint) => bigint,
  multiply: (a: bigint, b: bigint) => bigint,
  one: bigint
): bigint {
  const tableSize = 1 << window;
  const table = new Array<bigint>(tableSize);
  table[1] = base;

  if (tableSize > 2) {
    const base2 = square(base);
    for (let i = 3; i < tableSize; i += 2) {
      table[i] = multiply(table[i - 2]!, base2);
    }
  }

  let result = one;
  let i = 0;
  const bitLen = bits.length;

  while (i < bitLen) {
    if (bits.charCodeAt(i) === 48) {
      result = square(result);
      i++;
      continue;
    }

    let j = Math.min(i + window, bitLen);
    while (bits.charCodeAt(j - 1) === 48) {
      j--;
    }

    let win = 0;
    for (let k = i; k < j; k++) {
      win = (win << 1) | (bits.charCodeAt(k) === 49 ? 1 : 0);
    }

    for (let k = i; k < j; k++) {
      result = square(result);
    }
    result = multiply(result, table[win]!);
    i = j;
  }

  return result;
}

/**
 * Modular exponentiation: compute x^y mod p using square-and-multiply.
 */
export function modpow(x: bigint, y: bigint, p: bigint): bigint {
  if (p === 1n) return 0n;
  if (y === 0n) return 1n % p;
  if (y === 1n) return x % p;
  if (y === 2n) {
    const v = x % p;
    return (v * v) % p;
  }

  let base = x % p;
  const expBits = bigintBitLength(y);

  if (expBits <= MODPOW_WINDOW_THRESHOLD_BITS) {
    return modpowClassic(base, y, p);
  }

  const window = selectWindowSize(expBits);
  const bits = y.toString(2);

  if (shouldUseMontgomeryForModpow(p, expBits)) {
    const mont = getMontgomeryReducerCached(p);
    const baseMont = mont.toMontgomery(base);
    const oneMont = mont.toMontgomery(1n);
    const resultMont = modpowWindowedCore(
      baseMont,
      bits,
      window,
      (a) => mont.square(a),
      (a, b) => mont.multiply(a, b),
      oneMont
    );
    return mont.fromMontgomery(resultMont);
  }

  return modpowWindowedCore(
    base,
    bits,
    window,
    (a) => (a * a) % p,
    (a, b) => (a * b) % p,
    1n
  );
}

/**
 * Simultaneous exponentiation: compute a^e * b^f mod m efficiently.
 */
export function modpowProduct(
  a: bigint,
  e: bigint,
  b: bigint,
  f: bigint,
  m: bigint
): bigint {
  if (m === 1n) return 0n;
  if (e === 0n) return modpow(b, f, m);
  if (f === 0n) return modpow(a, e, m);

  let baseA = a % m;
  let baseB = b % m;

  const eBits = bigintBitLength(e);
  const fBits = bigintBitLength(f);
  const maxBits = Math.max(eBits, fBits);

  if (shouldUseMontgomeryForModpow(m, maxBits)) {
    const mont = getMontgomeryReducerCached(m);
    const oneMont = mont.toMontgomery(1n);
    const aMont = mont.toMontgomery(baseA);
    const bMont = mont.toMontgomery(baseB);
    const abMont = mont.multiply(aMont, bMont);

    let result = oneMont;
    for (let i = maxBits - 1; i >= 0; i--) {
      result = mont.square(result);
      const ea = (e >> BigInt(i)) & 1n;
      const fb = (f >> BigInt(i)) & 1n;
      if (ea === 1n && fb === 1n) {
        result = mont.multiply(result, abMont);
      } else if (ea === 1n) {
        result = mont.multiply(result, aMont);
      } else if (fb === 1n) {
        result = mont.multiply(result, bMont);
      }
    }
    return mont.fromMontgomery(result);
  }

  const ab = (baseA * baseB) % m;
  let result = 1n;
  for (let i = maxBits - 1; i >= 0; i--) {
    result = (result * result) % m;
    const ea = (e >> BigInt(i)) & 1n;
    const fb = (f >> BigInt(i)) & 1n;
    if (ea === 1n && fb === 1n) {
      result = (result * ab) % m;
    } else if (ea === 1n) {
      result = (result * baseA) % m;
    } else if (fb === 1n) {
      result = (result * baseB) % m;
    }
  }
  return result;
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

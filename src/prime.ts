import { bigintByteLength, modpow } from "./utils.ts";

/**
 * Precomputed small primes up to 1000 for trial division.
 */
const SMALL_PRIMES: bigint[] = (() => {
  const limit = 1000;
  const sieve = new Uint8Array(limit + 1);
  const primes: bigint[] = [];
  for (let i = 2; i <= limit; i++) {
    if (sieve[i] === 0) {
      primes.push(BigInt(i));
      for (let j = i * i; j <= limit; j += i) {
        sieve[j] = 1;
      }
    }
  }
  return primes;
})();

/**
 * Wheel factorization data for mod-210 (2*3*5*7).
 * Used to skip candidates divisible by small primes during prime search.
 */
const PRIME_WHEEL = (() => {
  const mod = 210;
  const residues: number[] = [];
  for (let r = 1; r < mod; r += 2) {
    if (r % 3 !== 0 && r % 5 !== 0 && r % 7 !== 0) {
      residues.push(r);
    }
  }
  const increments: number[] = [];
  for (let i = 0; i < residues.length; i++) {
    const cur = residues[i]!;
    const next = residues[(i + 1) % residues.length]!;
    increments.push((next - cur + mod) % mod);
  }
  return { mod, residues, increments };
})();

/**
 * Align a candidate to the nearest valid wheel residue.
 */
function alignToWheel(p: bigint): { p: bigint; idx: number } {
  const mod = PRIME_WHEEL.mod;
  const residues = PRIME_WHEEL.residues;
  const m = Number(p % BigInt(mod));
  for (let i = 0; i < residues.length; i++) {
    const r = residues[i]!;
    if (m <= r) {
      return { p: p + BigInt(r - m), idx: i };
    }
  }
  return { p: p + BigInt(mod - m + residues[0]!), idx: 0 };
}

export interface IsPrimeOptions {
  /** Number of Miller-Rabin rounds (default: 32) */
  rounds?: number;
}

/**
 * Deterministic witnesses for Miller-Rabin that give correct results
 * for numbers up to certain bounds.
 */
const DETERMINISTIC_WITNESSES: bigint[] = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];

/**
 * Perform a single Miller-Rabin round with witness a.
 * Returns false if n is definitely composite, true if probably prime.
 */
function millerRabinRound(n: bigint, d: bigint, s: number, a: bigint): boolean {
  let x = modpow(a, d, n);
  if (x === 1n || x === n - 1n) {
    return true;
  }

  for (let r = 1; r < s; r++) {
    x = (x * x) % n;
    if (x === n - 1n) {
      return true;
    }
    if (x === 1n) {
      return false;
    }
  }

  return false;
}

/**
 * Test if n is prime using Miller-Rabin primality test.
 *
 * First performs trial division against small primes, then runs
 * the specified number of Miller-Rabin rounds for probabilistic testing.
 * For numbers < 3,317,044,064,679,887,385,961,981, uses deterministic witnesses.
 *
 * @param n - The number to test
 * @param options - Configuration options
 * @returns true if n is probably prime, false if definitely composite
 */
export function isPrime(n: bigint, options: IsPrimeOptions = {}): boolean {
  const k = options.rounds ?? 32;

  if (n < 2n) {
    return false;
  }
  if (n === 2n || n === 3n) {
    return true;
  }
  if ((n & 1n) === 0n) {
    return false;
  }

  // Trial division against small primes
  for (const p of SMALL_PRIMES) {
    if (n === p) {
      return true;
    }
    if (n % p === 0n) {
      return false;
    }
  }

  // Write n - 1 as 2^s * d where d is odd
  let d = n - 1n;
  let s = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s++;
  }

  const nMinus1 = n - 1n;

  // For smaller numbers, use deterministic witnesses
  // Witnesses {2,3,5,7,11,13,17,19,23,29,31,37} work for n < 318,665,857,834,031,151,167,461
  if (n < 318665857834031151167461n) {
    for (const a of DETERMINISTIC_WITNESSES) {
      if (a >= nMinus1) break;
      if (!millerRabinRound(n, d, s, a)) {
        return false;
      }
    }
    return true;
  }

  // For larger numbers, use random witnesses
  const nBytes = bigintByteLength(n);
  const nMinus4 = n - 4n;
  const rand = new Uint8Array(nBytes * k);
  crypto.getRandomValues(rand);

  for (let i = 0; i < k; i++) {
    // Generate random witness in [2, n-2]
    let r = 0n;
    const off = i * nBytes;
    for (let j = 0; j < nBytes; j++) {
      r = (r << 8n) + BigInt(rand[off + j]!);
    }
    const a = 2n + (r % nMinus4);

    if (!millerRabinRound(n, d, s, a)) {
      return false;
    }
  }

  return true;
}

export interface GetPrimeOptions {
  /** Bit length of the prime (default: 256) */
  bits?: number;
  /** Number of Miller-Rabin rounds (default: 32) */
  rounds?: number;
}

/**
 * Generate a random prime of the specified bit length.
 *
 * Uses wheel sieving to skip candidates divisible by 2, 3, 5, 7,
 * then applies Miller-Rabin primality testing.
 *
 * @param options - Configuration options
 * @returns A random prime number
 */
export function getPrime(options: GetPrimeOptions = {}): bigint {
  const bits = options.bits ?? 256;
  const rounds = options.rounds ?? 32;
  const byteLen = Math.ceil(bits / 8);
  const x = new Uint8Array(byteLen);
  const max = (1n << BigInt(bits)) - 1n;

  while (true) {
    crypto.getRandomValues(x);

    // Set high bit to ensure correct bit length
    x[0] = x[0]! | 0x80;
    // Set low bit to ensure odd
    x[x.length - 1] = x[x.length - 1]! | 1;

    let p = BigInt("0x" + Buffer.from(x).toString("hex"));
    let aligned = alignToWheel(p);

    if (aligned.p > max) {
      continue;
    }

    p = aligned.p;
    let idx = aligned.idx;

    while (p <= max) {
      if (isPrime(p, { rounds })) {
        return p;
      }
      p += BigInt(PRIME_WHEEL.increments[idx]!);
      idx = (idx + 1) % PRIME_WHEEL.increments.length;
    }
  }
}

/**
 * Find the next prime >= n.
 * Uses wheel factorization to skip candidates divisible by small primes.
 *
 * @param n - Starting point
 * @param options - Configuration options
 * @returns The smallest prime >= n
 */
export function nextPrime(n: bigint, options: IsPrimeOptions = {}): bigint {
  if (n <= 2n) return 2n;
  if (n === 3n) return 3n;
  if (n <= 5n) return 5n;
  if (n <= 7n) return 7n;

  // Align to wheel and iterate
  let aligned = alignToWheel(n);
  let p = aligned.p;
  let idx = aligned.idx;

  // Check if we skipped over n with a smaller prime
  if (p > n) {
    // Check if any small prime >= n exists before p
    if (n <= 2n) return 2n;
    if (n <= 3n) return 3n;
    if (n <= 5n) return 5n;
    if (n <= 7n) return 7n;
  }

  while (true) {
    if (isPrime(p, options)) {
      return p;
    }
    p += BigInt(PRIME_WHEEL.increments[idx]!);
    idx = (idx + 1) % PRIME_WHEEL.increments.length;
  }
}

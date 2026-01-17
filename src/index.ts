/**
 * Wesolowski Verifiable Delay Function (VDF) implementation.
 *
 * VDFs require a specified number of sequential computations to evaluate,
 * but can be verified quickly. This implementation uses the Wesolowski
 * construction with RSA groups.
 *
 * @example
 * ```typescript
 * import { evaluate, generateProof, verify, RSA_2048 } from "wesolowski-vdf";
 *
 * // Evaluate VDF with t = 100000 sequential squarings
 * const output = evaluate(x, { n: RSA_2048, t: 100000 });
 *
 * // Generate proof
 * const proof = await generateProof(output);
 *
 * // Verify proof (fast)
 * const valid = verify(proof);
 * ```
 *
 * @packageDocumentation
 */

// Main VDF functions
export {
  evaluate,
  deriveChallenge,
  prove,
  generateProof,
  verify,
  verifyWithChallenge,
  RSA_2048,
  RSA_3072,
  RSA_4096,
  type VDFParams,
  type VDFOutput,
  type VDFProof,
} from "./vdf.ts";

// Prime utilities (for advanced usage)
export {
  isPrime,
  getPrime,
  nextPrime,
  type IsPrimeOptions,
  type GetPrimeOptions,
} from "./prime.ts";

// Low-level utilities (for advanced usage)
export {
  modpow,
  modpowProduct,
  gcd,
  bigintToBytes,
  bytesToBigint,
  bigintByteLength,
  bigintBitLength,
  bigintToFixedBytes,
  concatBytes,
  u32be,
  u64be,
} from "./utils.ts";

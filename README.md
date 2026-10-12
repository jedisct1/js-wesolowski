# Wesolowski VDF for JavaScript

A TypeScript implementation of the Wesolowski Verifiable Delay Function (VDF).

This implementation uses a construction with RSA groups, where computing h = x^(2^t) mod n requires t sequential squarings (no parallelization possible), but verification requires only O(log t) exponentiations.

## Installation

```sh
bun install
```

## Usage

```typescript
import {
  evaluate,
  generateProof,
  verify,
  RSA_2048,
} from "wesolowski-vdf";

// Evaluate VDF: h = x^(2^t) mod n
const output = evaluate(x, { n: RSA_2048, t: 100_000 });

// Generate proof
const proof = await generateProof(output);

// Verify proof (fast)
const valid = verify(proof);
```

### Running the Example

```sh
bun run examples/basic.ts
```

## Performance

Pass the object returned by `evaluate()` directly to `generateProof()` or `prove()` for the fastest proof generation.
For RSA-sized odd moduli and 1,000 ≤ `t` ≤ 1,000,000, evaluation retains up to 1,024 intermediate powers and the prover combines them instead of repeating most of the squarings.

All `t` sequential evaluation steps still run, and the proof format and challenge derivation are unchanged.

## API

### Core Functions

#### `evaluate(x, params)`

Compute the VDF output h = x^(2^t) mod n.

```typescript
const output = evaluate(x, { n: RSA_2048, t: 100_000 });
// output.h is the result
```

#### `generateProof(output, nonce?)`

Generate a Wesolowski proof for a VDF output.

```typescript
const proof = await generateProof(output);
// proof contains: x, h, t, n, pi, l, nonce
```

#### `verify(proof)`

Verify a proof by checking that pi^l * x^r = h (mod n).

```typescript
const valid = verify(proof); // true or false
```

#### `verifyWithChallenge(proof)`

Full verification that also re-derives the challenge prime from the transcript.

```typescript
const valid = await verifyWithChallenge(proof);
```

### Constants

Three RSA-sized moduli are provided:

```typescript
import { RSA_2048, RSA_3072, RSA_4096 } from "wesolowski-vdf";
```

| Constant   | Bits | Source                                         |
| ---------- | ---- | ---------------------------------------------- |
| `RSA_2048` | 2048 | RSA Factoring Challenge                        |
| `RSA_3072` | 3072 | Deterministic (seed: `wesolowski-vdf-3072-v1`) |
| `RSA_4096` | 4096 | Deterministic (seed: `wesolowski-vdf-4096-v1`) |

`RSA_2048` is from the RSA Factoring Challenge with unknown factorization.
`RSA_3072` and `RSA_4096` are documented as generated deterministically by hashing public seeds to derive their factors.
Treat those two constants as arithmetic and interoperability fixtures, not as secure VDF parameters: reproducible factors would defeat the delay assumption.
A production VDF needs a modulus whose factorization is unknown.

### Prime Utilities

For advanced usage, prime generation and testing functions are exported:

```typescript
import { isPrime, getPrime, nextPrime } from "wesolowski-vdf";

// Test primality (Miller-Rabin)
isPrime(n, { rounds: 32 });

// Generate random prime
getPrime({ bits: 256, rounds: 32 });

// Find next prime >= n
nextPrime(n);
```

## Mathematical Background

The Wesolowski VDF works as follows:

1. Evaluation: Compute h = x^(2^t) mod n by performing t sequential squarings
2. Challenge: Derive prime l via Fiat-Shamir (hash of transcript)
3. Proof: Compute pi = x^floor(2^t / l) mod n using long division in the exponent
4. Verification: Check that pi^l * x^r = h (mod n), where r = 2^t mod l

The key insight is that while computing h requires t sequential squarings, verification only requires computing two modular exponentiations (with exponents l and r), which takes O(log t) operations.

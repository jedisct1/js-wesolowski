import {
  evaluate,
  deriveChallenge,
  prove,
  verify,
  RSA_2048,
  type VDFOutput,
} from "../src/vdf.ts";

const SMALL_P = 1000000007n;
const SMALL_Q = 1000000009n;
const SMALL_MODULUS = SMALL_P * SMALL_Q;

const SMALL_T = 1000;
const LARGE_T = 300;

const SCALE = Number(process.env.BENCH_SCALE ?? "1");

function bench(name: string, iterations: number, fn: () => bigint | boolean): bigint {
  let sink = 0n;
  // Warmup
  for (let i = 0; i < Math.min(5, iterations); i++) {
    const res = fn();
    sink ^= typeof res === "boolean" ? (res ? 1n : 0n) : res;
  }
  const start = Bun.nanoseconds();
  for (let i = 0; i < iterations; i++) {
    const res = fn();
    sink ^= typeof res === "boolean" ? (res ? 1n : 0n) : res;
  }
  const totalNs = Bun.nanoseconds() - start;
  const totalMs = Number(totalNs) / 1e6;
  const avgUs = Number(totalNs) / iterations / 1e3;
  console.log(
    `${name.padEnd(28)} ${iterations.toString().padStart(6)} iters  ${totalMs.toFixed(
      2
    )} ms  (${avgUs.toFixed(2)} µs/op)`
  );
  return sink;
}

function config(iterations: number): number {
  return Math.max(1, Math.floor(iterations * SCALE));
}

async function prepare(
  n: bigint,
  x: bigint,
  t: number
): Promise<{ output: VDFOutput; l: bigint; proof: VDFOutput & { pi: bigint; l: bigint; nonce: Uint8Array } }> {
  const output = evaluate(x, { n, t });
  const nonce = new Uint8Array(32);
  nonce.fill(1);
  const l = await deriveChallenge(output, nonce);
  const pi = prove(output, l);
  return { output, l, proof: { ...output, pi, l, nonce } };
}

async function main(): Promise<void> {
  const smallX = 123456791n;
  const largeX = 2n;

  const small = await prepare(SMALL_MODULUS, smallX, SMALL_T);
  const large = await prepare(RSA_2048, largeX, LARGE_T);

  console.log("Wesolowski VDF micro-bench");
  console.log(
    `scale=${SCALE}  small(t=${SMALL_T}, n=~${SMALL_MODULUS.toString(2).length} bits)  large(t=${LARGE_T}, n=2048 bits)`
  );
  console.log("");

  bench(
    "evaluate (small)",
    config(40),
    () => evaluate(smallX, { n: SMALL_MODULUS, t: SMALL_T }).h
  );
  bench("prove (small)", config(40), () => prove(small.output, small.l));
  bench("verify (small)", config(200), () => verify(small.proof));

  console.log("");

  bench(
    "evaluate (RSA_2048)",
    config(10),
    () => evaluate(largeX, { n: RSA_2048, t: LARGE_T }).h
  );
  bench("prove (RSA_2048)", config(10), () => prove(large.output, large.l));
  bench("verify (RSA_2048)", config(80), () => verify(large.proof));
}

await main();

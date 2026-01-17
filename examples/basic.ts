/**
 * Basic example demonstrating VDF evaluation, proving, and verification.
 */

import {
	evaluate,
	generateProof,
	verify,
	verifyWithChallenge,
	RSA_2048,
} from "../src/index.ts";

async function main() {
	// Parameters
	const t = 100_000; // Number of sequential squarings
	const n = RSA_2048; // RSA-2048 modulus

	// Derive input x from a seed (in practice, this could come from any source)
	const seed = new TextEncoder().encode("example-seed");
	const hash = await crypto.subtle.digest("SHA-256", seed);
	const x = (BigInt(`0x${Buffer.from(hash).toString("hex")}`) % (n - 2n)) + 2n;

	console.log("VDF Parameters:");
	console.log(`  t = ${t.toLocaleString()} sequential squarings`);
	console.log(`  n = RSA-2048 (${n.toString().slice(0, 20)}...)`);
	console.log(`  x = ${x.toString().slice(0, 40)}...`);
	console.log();

	// Evaluate VDF (slow - requires t sequential operations)
	console.log("Evaluating VDF...");
	const startEval = performance.now();
	const output = evaluate(x, { n, t });
	const evalTime = performance.now() - startEval;
	console.log(`  h = ${output.h.toString().slice(0, 40)}...`);
	console.log(`  Evaluation time: ${(evalTime / 1000).toFixed(2)}s`);
	console.log();

	// Generate proof (also requires t operations, but proves correctness)
	console.log("Generating proof...");
	const startProve = performance.now();
	const proof = await generateProof(output);
	const proveTime = performance.now() - startProve;
	console.log(`  π = ${proof.pi.toString().slice(0, 40)}...`);
	console.log(`  l = ${proof.l}`);
	console.log(`  Proof generation time: ${(proveTime / 1000).toFixed(2)}s`);
	console.log();

	// Verify proof (fast - only O(log t) operations)
	console.log("Verifying proof...");
	const startVerify = performance.now();
	const valid = verify(proof);
	const verifyTime = performance.now() - startVerify;
	console.log(`  Valid: ${valid}`);
	console.log(`  Verification time: ${verifyTime.toFixed(2)}ms`);
	console.log();

	// Full verification (re-derives challenge from transcript)
	console.log("Full verification with challenge re-derivation...");
	const startFullVerify = performance.now();
	const fullValid = await verifyWithChallenge(proof);
	const fullVerifyTime = performance.now() - startFullVerify;
	console.log(`  Valid: ${fullValid}`);
	console.log(`  Full verification time: ${fullVerifyTime.toFixed(2)}ms`);
}

main().catch(console.error);

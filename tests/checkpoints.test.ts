import { describe, expect, test } from "bun:test";
import {
	deriveChallenge,
	evaluate,
	generateProof,
	prove,
	RSA_2048,
	RSA_3072,
	RSA_4096,
	verify,
	verifyWithChallenge,
	type VDFOutput,
} from "../src/vdf.ts";

function referencePower(
	base: bigint,
	exponent: bigint,
	modulus: bigint,
): bigint {
	let result = 1n;
	for (const bit of exponent.toString(2)) {
		result = (result * result) % modulus;
		if (bit === "1") result = (result * base) % modulus;
	}
	return result;
}

function referenceEvaluation(x: bigint, n: bigint, t: number): bigint {
	let result = x;
	for (let i = 0; i < t; i++) result = (result * result) % n;
	return result;
}

function referenceProof({ x, n, t }: VDFOutput, l: bigint): bigint {
	return referencePower(x, (1n << BigInt(t)) / l, n);
}

const challenge = (1n << 511n) + 0x123456789abcdefn;

function expectReferenceProof(output: VDFOutput, l: bigint): bigint {
	const pi = prove(output, l);
	expect(pi).toBe(referenceProof(output, l));
	return pi;
}

describe("checkpoint proof differential tests", () => {
	for (const [name, n, t] of [
		["RSA-2048", RSA_2048, 1000],
		["RSA-3072", RSA_3072, 1019],
		["RSA-4096", RSA_4096, 1040],
	] as const) {
		test(`${name} has a nontrivial Fiat-Shamir proof`, async () => {
			const output = evaluate(2n, { n, t });
			expect(output.h).toBe(referenceEvaluation(2n, n, t));
			const nonce = new Uint8Array(32).fill(42);
			const proof = await generateProof(output, nonce);
			expect(proof.pi).toBe(referenceProof(output, proof.l));
			expect(proof.pi).not.toBe(1n);
			const remainder = (1n << BigInt(t)) % proof.l;
			expect(
				(referencePower(proof.pi, proof.l, n) *
					referencePower(output.x, remainder, n)) %
					n,
			).toBe(output.h);
			expect(verify(proof)).toBe(true);
			expect(await verifyWithChallenge(proof)).toBe(true);
			expect(await verifyWithChallenge({ ...proof, pi: proof.pi + 1n })).toBe(
				false,
			);
			expect(
				await verifyWithChallenge({ ...proof, h: (proof.h + 1n) % n }),
			).toBe(false);
			expect(await verifyWithChallenge({ ...proof, x: n - 2n })).toBe(false);
			expect(await verifyWithChallenge({ ...proof, t: t + 1 })).toBe(false);
			expect(await verifyWithChallenge({ ...proof, n: n + 2n })).toBe(false);
			expect(
				await verifyWithChallenge({
					...proof,
					nonce: new Uint8Array(32).fill(43),
				}),
			).toBe(false);
		});
	}

	for (const t of [
		999, 1000, 1001, 1007, 1008, 1009, 1023, 1024, 1025, 16383, 16384, 16385,
		20479, 20480, 20481,
	]) {
		test(`checkpoint and stride boundaries at t=${t}`, () => {
			const output = evaluate(2n, { n: RSA_2048, t });
			expect(output.h).toBe(referenceEvaluation(2n, RSA_2048, t));
			expectReferenceProof(output, challenge);
			expectReferenceProof(output, 2n);
		});
	}

	for (const t of [1, 16, 999, 1000, 1008]) {
		test(`challenge boundaries at t=${t}`, () => {
			const output = evaluate(2n, { n: RSA_2048, t });
			const twoToT = 1n << BigInt(t);
			for (const l of [
				1n,
				2n,
				3n,
				4n,
				15n,
				16n,
				17n,
				255n,
				256n,
				257n,
				twoToT - 1n,
				twoToT,
				twoToT + 1n,
				twoToT << 1n,
			]) {
				expectReferenceProof(output, l);
			}
		});
	}

	test("sparse, dense, and partial exponent chunks", () => {
		const output = evaluate(RSA_2048 - 2n, { n: RSA_2048, t: 1031 });
		for (const shift of [
			0, 1, 3, 4, 15, 16, 17, 31, 32, 33, 511, 512, 1029, 1030,
		]) {
			const powerOfTwo = 1n << BigInt(shift);
			expectReferenceProof(output, powerOfTwo);
			expectReferenceProof(output, powerOfTwo + 1n);
		}
	});

	for (const [name, n, x] of [
		["small odd", 77n, 2n],
		["small even", 100n, 3n],
		["custom 1016-bit odd", (1n << 1015n) + 643n, 2n],
		["custom 1017-bit odd", (1n << 1016n) + 643n, 2n],
		["custom 1024-bit odd", (1n << 1023n) + 643n, 2n],
		["custom 1024-bit even", (1n << 1023n) + 2n, 3n],
	] as const) {
		test(`${name} modulus matches the reference`, () => {
			for (const t of [999, 1000, 1001, 1025]) {
				const output = evaluate(x, { n, t });
				expect(output.h).toBe(referenceEvaluation(x, n, t));
				for (const l of [3n, 16n, 257n, challenge]) {
					expectReferenceProof(output, l);
				}
			}
		});
	}

	test("deterministic property matrix exercises varied quotient digits", () => {
		let state = 0x6d2b79f5n;
		for (let sample = 0; sample < 24; sample++) {
			let l = 0n;
			for (let limb = 0; limb < 16; limb++) {
				state = (state * 1664525n + 1013904223n) & 0xffff_ffffn;
				l = (l << 32n) | state;
			}
			l |= 1n << 511n;
			const n = sample % 2 === 0 ? RSA_2048 : (1n << 1023n) + 643n;
			const x = 1n << BigInt(sample + 1);
			const t = 1000 + Number(state % 97n);
			const output = evaluate(x, { n, t });
			expect(output.h).toBe(referenceEvaluation(x, n, t));
			expectReferenceProof(output, l);
			expectReferenceProof({ ...output }, l);
		}
	});

	test("copied, cloned, deserialized, and frozen outputs", () => {
		const output = evaluate(2n, { n: RSA_2048, t: 1000 });
		const decoded = JSON.parse(
			JSON.stringify({
				x: output.x.toString(),
				h: output.h.toString(),
				n: output.n.toString(),
				t: output.t,
			}),
		) as { x: string; h: string; n: string; t: number };
		const restored: VDFOutput = {
			x: BigInt(decoded.x),
			h: BigInt(decoded.h),
			n: BigInt(decoded.n),
			t: decoded.t,
		};
		const expected = referenceProof(output, challenge);
		for (const candidate of [
			output,
			{ ...output },
			structuredClone(output),
			restored,
			Object.freeze(output),
		]) {
			expect(prove(candidate, challenge)).toBe(expected);
		}
	});

	for (const field of ["x", "n", "t"] as const) {
		test(`changed ${field} cannot reuse stale checkpoint powers`, () => {
			const output = evaluate(2n, { n: RSA_2048, t: 1000 });
			const original = { ...output };
			expectReferenceProof(output, challenge);
			if (field === "x") output.x = RSA_2048 - 2n;
			if (field === "n") output.n = RSA_3072;
			if (field === "t") output.t = 1033;
			expectReferenceProof(output, challenge);
			Object.assign(output, original);
			expectReferenceProof(output, challenge);
		});
	}

	test("parameter objects are snapshotted during evaluation", () => {
		const params = { n: RSA_2048, t: 1000 };
		const output = evaluate(2n, params);
		params.n = RSA_4096;
		params.t = 1033;
		expect(output.n).toBe(RSA_2048);
		expect(output.t).toBe(1000);
		expectReferenceProof(output, challenge);
	});

	test("changed h affects Fiat-Shamir but not the proof exponent", async () => {
		const output = evaluate(2n, { n: RSA_2048, t: 1000 });
		const nonce = new Uint8Array(32).fill(17);
		const originalL = await deriveChallenge(output, nonce);
		const originalPi = expectReferenceProof(output, originalL);
		output.h = (output.h + 1n) % output.n;
		expect(prove(output, originalL)).toBe(originalPi);
		const changedL = await deriveChallenge(output, nonce);
		expect(changedL).not.toBe(originalL);
		const changedPi = expectReferenceProof(output, changedL);
		expect(
			await verifyWithChallenge({
				...output,
				l: changedL,
				pi: changedPi,
				nonce,
			}),
		).toBe(false);
	});

	test("repeated challenges do not consume or mutate checkpoints", () => {
		const output = evaluate(2n, { n: RSA_4096, t: 1009 });
		const original = { ...output };
		for (const l of [challenge, 3n, 16n, challenge + 2n, challenge]) {
			expectReferenceProof(output, l);
			expect(output).toEqual(original);
		}
	});

	test("unit challenge above the direct-exponent limit", () => {
		const output = evaluate(2n, { n: 101n, t: 1_000_001 });
		const expected = output.h;
		output.h = 0n;
		expect(prove(output, 1n)).toBe(expected);
	});

	test("reducer caches are not exposed to callers", async () => {
		const utils = await import("../src/utils.ts");
		expect("PRECOMPUTED_MONTGOMERY" in utils).toBe(false);
	});

	for (const t of [1_000_000, 1_000_001]) {
		test(`direct-exponent limit at t=${t}`, () => {
			const n = (1n << 1023n) + 643n;
			const output = evaluate(2n, { n, t });
			expect(output.h).toBe(referenceEvaluation(2n, n, t));
			expectReferenceProof(output, 257n);
		}, 20_000);
	}
});

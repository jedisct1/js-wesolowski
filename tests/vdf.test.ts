import { describe, test, expect } from "bun:test";
import {
	evaluate,
	deriveChallenge,
	prove,
	generateProof,
	verify,
	verifyWithChallenge,
	RSA_2048,
	RSA_3072,
	RSA_4096,
} from "../src/vdf.ts";
import { modpow } from "../src/utils.ts";

// Use a smaller modulus for faster tests (product of two primes)
const P = 1000000007n; // A known prime
const Q = 1000000009n; // Another known prime
const TEST_MODULUS = P * Q;

// A value guaranteed coprime to TEST_MODULUS (a prime different from P and Q)
const TEST_X = 123456791n;

describe("evaluate", () => {
	test("computes VDF output correctly", () => {
		const x = 2n;
		const t = 10;
		const output = evaluate(x, { n: TEST_MODULUS, t });

		// Manual verification: h = x^(2^t) mod n
		let expected = x;
		for (let i = 0; i < t; i++) {
			expected = (expected * expected) % TEST_MODULUS;
		}

		expect(output.h).toBe(expected);
		expect(output.x).toBe(x);
		expect(output.t).toBe(t);
		expect(output.n).toBe(TEST_MODULUS);
	});

	test("throws for x <= 0", () => {
		expect(() => evaluate(0n, { n: TEST_MODULUS, t: 10 })).toThrow(RangeError);
		expect(() => evaluate(-1n, { n: TEST_MODULUS, t: 10 })).toThrow(RangeError);
	});

	test("throws for x >= n", () => {
		expect(() => evaluate(TEST_MODULUS, { n: TEST_MODULUS, t: 10 })).toThrow(
			RangeError,
		);
	});

	test("throws for t <= 0", () => {
		expect(() => evaluate(2n, { n: TEST_MODULUS, t: 0 })).toThrow(RangeError);
		expect(() => evaluate(2n, { n: TEST_MODULUS, t: -1 })).toThrow(RangeError);
	});
});

describe("prove and verify", () => {
	test("generates valid proof for small t", () => {
		const x = TEST_X;
		const t = 100;
		const output = evaluate(x, { n: TEST_MODULUS, t });

		const nonce = new Uint8Array(32);
		crypto.getRandomValues(nonce);

		// This is async but we need to await it
		const testProof = async () => {
			const l = await deriveChallenge(output, nonce);
			const pi = prove(output, l);

			const proof = {
				...output,
				pi,
				l,
				nonce,
			};

			expect(verify(proof)).toBe(true);
		};

		return testProof();
	});

	test("verification fails with wrong pi", async () => {
		const x = TEST_X;
		const t = 100;
		const output = evaluate(x, { n: TEST_MODULUS, t });

		const nonce = new Uint8Array(32);
		crypto.getRandomValues(nonce);

		const l = await deriveChallenge(output, nonce);
		const pi = prove(output, l);

		const badProof = {
			...output,
			pi: pi + 1n, // Wrong proof
			l,
			nonce,
		};

		expect(verify(badProof)).toBe(false);
	});

	test("verification fails with wrong h", async () => {
		const x = TEST_X;
		const t = 100;
		const output = evaluate(x, { n: TEST_MODULUS, t });

		const nonce = new Uint8Array(32);
		crypto.getRandomValues(nonce);

		const l = await deriveChallenge(output, nonce);
		const pi = prove(output, l);

		const badProof = {
			...output,
			h: output.h + 1n, // Wrong output
			pi,
			l,
			nonce,
		};

		expect(verify(badProof)).toBe(false);
	});
});

describe("generateProof", () => {
	test("generates complete proof", async () => {
		const x = TEST_X;
		const t = 100;
		const output = evaluate(x, { n: TEST_MODULUS, t });

		const proof = await generateProof(output);

		expect(proof.x).toBe(x);
		expect(proof.h).toBe(output.h);
		expect(proof.t).toBe(t);
		expect(proof.n).toBe(TEST_MODULUS);
		expect(proof.pi).toBeDefined();
		expect(proof.l).toBeDefined();
		expect(proof.nonce.length).toBe(32);
	});

	test("proof passes verification", async () => {
		const x = TEST_X;
		const t = 100;
		const output = evaluate(x, { n: TEST_MODULUS, t });

		const proof = await generateProof(output);

		expect(verify(proof)).toBe(true);
	});

	test("proof passes full verification with challenge re-derivation", async () => {
		const x = TEST_X;
		const t = 100;
		const output = evaluate(x, { n: TEST_MODULUS, t });

		const proof = await generateProof(output);

		expect(await verifyWithChallenge(proof)).toBe(true);
	});
});

describe("verifyWithChallenge", () => {
	test("fails when l doesn't match transcript", async () => {
		const x = TEST_X;
		const t = 100;
		const output = evaluate(x, { n: TEST_MODULUS, t });

		const proof = await generateProof(output);

		// Tamper with l
		const badProof = {
			...proof,
			l: proof.l + 2n, // Increment by 2 to likely still be prime
		};

		expect(await verifyWithChallenge(badProof)).toBe(false);
	});
});

describe("RSA moduli", () => {
	test("RSA_2048 is 2048 bits", () => {
		expect(RSA_2048.toString().startsWith("2519590847565789")).toBe(true);
		expect(RSA_2048.toString(2).length).toBe(2048);
	});

	test("RSA_3072 is 3072 bits", () => {
		expect(RSA_3072.toString().startsWith("3015017089231152")).toBe(true);
		expect(RSA_3072.toString(2).length).toBe(3072);
	});

	test("RSA_4096 is 4096 bits", () => {
		expect(RSA_4096.toString().startsWith("7473529620511977")).toBe(true);
		expect(RSA_4096.toString(2).length).toBe(4096);
	});
});

describe("mathematical properties", () => {
	test("verification equation holds: π^l · x^r ≡ h (mod n)", async () => {
		const x = 7n;
		const t = 50;
		const n = TEST_MODULUS;
		const output = evaluate(x, { n, t });

		const nonce = new Uint8Array(32);
		crypto.getRandomValues(nonce);
		const l = await deriveChallenge(output, nonce);
		const pi = prove(output, l);

		// r = 2^t mod l
		const r = modpow(2n, BigInt(t), l);

		// π^l · x^r mod n should equal h
		const lhs = (modpow(pi, l, n) * modpow(x, r, n)) % n;
		expect(lhs).toBe(output.h);
	});
});

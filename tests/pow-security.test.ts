import {
	beforeAll,
	describe,
	expect,
	setSystemTime,
	spyOn,
	test,
} from "bun:test";
import {
	createPowServer,
	InMemoryReplayStore,
	solveChallenge,
	type PowChallenge,
	type PowSolution,
} from "../src/pow.ts";
import { deriveChallenge, RSA_2048, verify } from "../src/vdf.ts";

const secret = new Uint8Array(32).fill(29);
const context = "POST /purchase:session=alice:cart=123";
let challenge: PowChallenge;
let solution: PowSolution;

beforeAll(async () => {
	const server = await createPowServer({
		secret,
		iterations: 1000,
		consume: () => true,
	});
	challenge = await server.createChallenge(context);
	solution = await solveChallenge(challenge);
});

describe("PoW adversarial boundaries", () => {
	test("malformed canonical fields and policy mismatches never start prime derivation", async () => {
		let consumed = 0;
		const server = await createPowServer({
			secret,
			iterations: 1000,
			consume: () => {
				consumed++;
				return true;
			},
		});
		const digest = spyOn(crypto.subtle, "digest");
		try {
			for (const field of ["id", "x", "mac"] as const) {
				for (const value of [
					challenge[field].slice(1),
					challenge[field] + "0",
					"A".repeat(challenge[field].length),
					"0".repeat(challenge[field].length - 1) + "\n",
					"0x" + challenge[field].slice(2),
					null,
					0,
					{ toString: () => challenge[field] },
				]) {
					expect(
						await server.verifySolution(
							{ ...challenge, [field]: value },
							solution,
							context,
						),
					).toBe(false);
				}
			}
			for (const field of ["issuedAt", "expiresAt", "iterations"] as const) {
				for (const value of [
					NaN,
					Infinity,
					-Infinity,
					1000.5,
					"1000",
					Number.MAX_SAFE_INTEGER + 1,
				]) {
					expect(
						await server.verifySolution(
							{ ...challenge, [field]: value },
							solution,
							context,
						),
					).toBe(false);
				}
			}
			for (const field of ["h", "pi"] as const) {
				for (const value of [
					"0".repeat(512),
					RSA_2048.toString(16).padStart(512, "0"),
					"f".repeat(512),
					"0".repeat(511) + "\n",
					solution[field].slice(1),
					solution[field] + "0",
				]) {
					expect(
						await server.verifySolution(
							challenge,
							{ ...solution, [field]: value },
							context,
						),
					).toBe(false);
				}
			}
			for (const expected of [
				"",
				"x".repeat(257),
				"POST /purchase:session=bob:cart=123",
				"POST /purchase:session=alice:cart=124",
			]) {
				expect(await server.verifySolution(challenge, solution, expected)).toBe(
					false,
				);
			}
			for (const altered of [
				{ ...challenge, version: 2 },
				{ ...challenge, iterations: 1001 },
				{ ...challenge, expiresAt: challenge.expiresAt + 1 },
				{ ...challenge, context: context + ":other" },
				{ ...challenge, mac: "0".repeat(64) },
				{ ...challenge, id: "1".repeat(64) },
			])
				expect(
					await server.verifySolution(altered, solution, altered.context),
				).toBe(false);
			expect(consumed).toBe(0);
			expect(digest).not.toHaveBeenCalled();
		} finally {
			digest.mockRestore();
		}
	});

	test("client-chosen l and nonce cannot bypass the internally derived transcript", async () => {
		let consumed = 0;
		const server = await createPowServer({
			secret,
			iterations: 1000,
			consume: () => {
				consumed++;
				return true;
			},
		});
		const x = BigInt(`0x${challenge.x}`);
		const forged = {
			x,
			h: x,
			n: RSA_2048,
			t: 1000,
			pi: 1n,
			l: 3n,
			nonce: new Uint8Array(32),
		};
		expect(verify(forged)).toBe(true);
		const answer = { h: challenge.x, pi: "1".padStart(512, "0") };
		expect(await server.verifySolution(challenge, answer, context)).toBe(false);
		for (const field of ["l", "nonce", "n", "x", "t", "iterations"]) {
			expect(
				await server.verifySolution(
					challenge,
					{ ...solution, [field]: "3" },
					context,
				),
			).toBe(false);
		}
		expect(consumed).toBe(0);
		expect(await server.verifySolution(challenge, solution, context)).toBe(
			true,
		);
	});

	test("Buffer key bytes and ttl policy are snapshotted before key import awaits", async () => {
		const bytes = Buffer.from(secret);
		const options = {
			secret: bytes,
			iterations: 1000,
			ttlMs: 60_000,
			consume: () => true,
		};
		const pending = createPowServer(options);
		bytes.fill(0);
		options.ttlMs = 1000;
		options.consume = () => false;
		const server = await pending;
		expect(await server.verifySolution(challenge, solution, context)).toBe(
			true,
		);
	});

	test("bounded escaped context round trips without application-controlled serialization", async () => {
		const server = await createPowServer({
			secret,
			iterations: 1000,
			consume: new InMemoryReplayStore().consume,
		});
		const expected = '\u0000\ud800\\"'.repeat(64);
		expect(expected.length).toBe(256);
		const ticket = JSON.parse(
			JSON.stringify(await server.createChallenge(expected)),
		);
		const answer = await solveChallenge(ticket);
		let serialized = false;
		Object.setPrototypeOf(ticket, {
			toJSON() {
				serialized = true;
				throw new Error("must not serialize caller object");
			},
		});
		expect(await server.verifySolution(ticket, answer, expected)).toBe(true);
		expect(serialized).toBe(false);
		expect(await server.verifySolution(ticket, answer, expected)).toBe(false);
	});

	test("async backend failures and truthy non-booleans fail closed", async () => {
		for (const result of [1, "true", {}, new Boolean(true), undefined, null]) {
			const server = await createPowServer({
				secret,
				iterations: 1000,
				consume: (async () => result) as unknown as () => Promise<boolean>,
			});
			expect(await server.verifySolution(challenge, solution, context)).toBe(
				false,
			);
		}
		const server = await createPowServer({
			secret,
			iterations: 1000,
			consume: async () => {
				throw new Error("lost claim response");
			},
		});
		await expect(
			server.verifySolution(challenge, solution, context),
		).rejects.toThrow("lost claim response");
	});

	test("crypto failure and expiration during HMAC verification cannot consume", async () => {
		let consumed = 0;
		const server = await createPowServer({
			secret,
			iterations: 1000,
			consume: () => {
				consumed++;
				return true;
			},
		});
		const original = crypto.subtle.verify.bind(crypto.subtle);
		const broken = spyOn(crypto.subtle, "verify").mockRejectedValueOnce(
			new Error("crypto unavailable"),
		);
		try {
			await expect(
				server.verifySolution(challenge, solution, context),
			).rejects.toThrow("crypto unavailable");
		} finally {
			broken.mockRestore();
		}
		const delayed = spyOn(crypto.subtle, "verify").mockImplementation(
			async (...args) => {
				const valid = await original(...args);
				setSystemTime(new Date(challenge.expiresAt));
				return valid;
			},
		);
		try {
			expect(await server.verifySolution(challenge, solution, context)).toBe(
				false,
			);
		} finally {
			delayed.mockRestore();
			setSystemTime();
		}
		expect(consumed).toBe(0);
	});

	test("solver cap rejects excessive public work before SHA-512 or evaluation", async () => {
		const digest = spyOn(crypto.subtle, "digest");
		try {
			await expect(
				solveChallenge({ ...challenge, iterations: 10_000_000 }),
			).rejects.toThrow("maxIterations");
			for (const maxIterations of [999, 1000.5, Infinity, NaN, 10_000_001]) {
				await expect(
					solveChallenge(challenge, { maxIterations }),
				).rejects.toThrow("maxIterations");
			}
			expect(digest).not.toHaveBeenCalled();
		} finally {
			digest.mockRestore();
		}
	});

	test("valid wrapper proofs still verify beyond the core challenge cache capacity", async () => {
		for (let i = 0; i < 130; i++) {
			const nonce = new Uint8Array(32);
			nonce[0] = 123;
			nonce[31] = i;
			await deriveChallenge({ x: 4n, h: 16n, n: RSA_2048, t: 1000 }, nonce);
		}
		const server = await createPowServer({
			secret,
			iterations: 1000,
			consume: new InMemoryReplayStore().consume,
		});
		const ticket = await server.createChallenge(context);
		const answer = await solveChallenge(ticket);
		expect(await server.verifySolution(ticket, answer, context)).toBe(true);
		expect(await server.verifySolution(ticket, answer, context)).toBe(false);
	}, 30_000);
});

describe("replay retention under capacity and clock pressure", () => {
	test("large overflow never evicts any live claim", () => {
		const now = Date.now();
		try {
			setSystemTime(new Date(now));
			const capacity = 4096;
			const store = new InMemoryReplayStore(capacity);
			const id = (i: number) => i.toString(16).padStart(64, "0");
			for (let i = 0; i < capacity; i++)
				expect(store.consume(id(i), now + 60_000)).toBe(true);
			for (let i = capacity; i < capacity + 32; i++)
				expect(store.consume(id(i), now + 60_000)).toBe(false);
			for (let i = 0; i < capacity; i++)
				expect(store.consume(id(i), now + 60_000)).toBe(false);
			setSystemTime(new Date(now + 60_000));
			expect(store.consume(id(capacity), now + 61_000)).toBe(true);
		} finally {
			setSystemTime();
		}
	});

	test("expiration eviction followed by rollback cannot resurrect the old ticket", () => {
		const now = Date.now();
		const store = new InMemoryReplayStore(2);
		try {
			setSystemTime(new Date(now));
			expect(store.consume("01".repeat(32), now + 1000)).toBe(true);
			setSystemTime(new Date(now + 1000));
			expect(store.consume("02".repeat(32), now + 2000)).toBe(true);
			setSystemTime(new Date(now + 2000));
			expect(store.consume("02".repeat(32), now + 2000)).toBe(false);
			setSystemTime(new Date(now));
			expect(store.consume("01".repeat(32), now + 1000)).toBe(false);
		} finally {
			setSystemTime();
		}
	});
});

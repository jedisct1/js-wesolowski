import { beforeAll, describe, expect, setSystemTime, test } from "bun:test";
import {
	createPowServer,
	solveChallenge,
	InMemoryReplayStore,
	MAX_POW_REQUEST_BYTES,
	type PowChallenge,
	type PowSolution,
} from "../src/index.ts";
import { gcd } from "../src/utils.ts";
import { RSA_2048 } from "../src/vdf.ts";

const secret = new Uint8Array(32).fill(17);
const context = "GET /private:session-123";
const options = { secret, iterations: 1000 };
let challenge: PowChallenge;
let solution: PowSolution;

beforeAll(async () => {
	const server = await createPowServer({ ...options, consume: () => true });
	challenge = await server.createChallenge(context);
	solution = await solveChallenge(challenge);
});

async function sign(fields: PowChallenge): Promise<PowChallenge> {
	const key = await crypto.subtle.importKey(
		"raw",
		secret,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const data = new TextEncoder().encode(
		JSON.stringify([
			"wesolowski-web-pow-rsa2048-v1",
			fields.version,
			fields.id,
			fields.x,
			fields.iterations,
			fields.issuedAt,
			fields.expiresAt,
			fields.context,
		]),
	);
	const mac = await crypto.subtle.sign("HMAC", key, data);
	return {
		...fields,
		mac: Array.from(new Uint8Array(mac), (b) =>
			b.toString(16).padStart(2, "0"),
		).join(""),
	};
}

describe("single-use proof of work", () => {
	test("round trips over JSON and accepts exactly once", async () => {
		const store = new InMemoryReplayStore();
		const server = await createPowServer({
			...options,
			consume: store.consume,
		});
		const ticket = JSON.parse(JSON.stringify(challenge));
		const answer = JSON.parse(JSON.stringify(solution));
		expect(await server.verifySolution(ticket, answer, context)).toBe(true);
		expect(await server.verifySolution(ticket, answer, context)).toBe(false);
		expect(
			new TextEncoder().encode(JSON.stringify({ challenge, solution })).length,
		).toBeLessThan(MAX_POW_REQUEST_BYTES);
	});

	test("fresh tickets have independent nontrivial inputs and identifiers", async () => {
		const server = await createPowServer({ ...options, consume: () => true });
		const other = await server.createChallenge(context);
		expect(other.id).not.toBe(challenge.id);
		expect(other.x).not.toBe(challenge.x);
		for (const item of [challenge, other]) {
			const x = BigInt(`0x${item.x}`);
			expect(x > 1n && x < RSA_2048 - 1n).toBe(true);
			expect(gcd(x, RSA_2048)).toBe(1n);
		}
		expect(await server.verifySolution(other, solution, context)).toBe(false);
	});

	test("concurrent requests and replicas share one atomic claim", async () => {
		const store = new InMemoryReplayStore();
		const a = await createPowServer({ ...options, consume: store.consume });
		const b = await createPowServer({ ...options, consume: store.consume });
		const results = await Promise.all(
			Array.from({ length: 8 }, (_, i) =>
				(i % 2 ? a : b).verifySolution(challenge, solution, context),
			),
		);
		expect(results.filter(Boolean)).toHaveLength(1);
	});

	test("different context, key, and server difficulty fail without consuming", async () => {
		let calls = 0;
		const consume = () => {
			calls++;
			return true;
		};
		const server = await createPowServer({ ...options, consume });
		expect(
			await server.verifySolution(
				challenge,
				solution,
				"POST /transfer:session-123",
			),
		).toBe(false);
		expect(
			await server.verifySolution(
				challenge,
				solution,
				"GET /private:session-456",
			),
		).toBe(false);
		const otherKey = await createPowServer({
			...options,
			secret: new Uint8Array(32).fill(18),
			consume,
		});
		expect(await otherKey.verifySolution(challenge, solution, context)).toBe(
			false,
		);
		const harder = await createPowServer({
			...options,
			iterations: 1001,
			consume,
		});
		expect(await harder.verifySolution(challenge, solution, context)).toBe(
			false,
		);
		expect(calls).toBe(0);
	});

	test("every authenticated field is bound", async () => {
		let calls = 0;
		const server = await createPowServer({
			...options,
			consume: () => {
				calls++;
				return true;
			},
		});
		const alterations = [
			{ id: "00".repeat(32) },
			{ x: "00".repeat(255) + "04" },
			{ iterations: 1001 },
			{ issuedAt: challenge.issuedAt - 1, expiresAt: challenge.expiresAt - 1 },
			{ expiresAt: challenge.expiresAt + 1 },
			{ context: "other context" },
			{ mac: "00".repeat(32) },
		];
		for (const change of alterations) {
			const ticket = { ...challenge, ...change };
			expect(
				await server.verifySolution(ticket, solution, ticket.context),
			).toBe(false);
		}
		expect(calls).toBe(0);
	});

	test("a bad proof does not consume a valid challenge", async () => {
		const store = new InMemoryReplayStore();
		const server = await createPowServer({
			...options,
			consume: store.consume,
		});
		const bad = {
			...solution,
			pi: ((BigInt(`0x${solution.pi}`) + 1n) % RSA_2048)
				.toString(16)
				.padStart(512, "0"),
		};
		expect(await server.verifySolution(challenge, bad, context)).toBe(false);
		expect(await server.verifySolution(challenge, solution, context)).toBe(
			true,
		);
	});

	test("input objects are snapshotted before the first await", async () => {
		const server = await createPowServer({
			...options,
			consume: new InMemoryReplayStore().consume,
		});
		const ticket = { ...challenge };
		const answer = { ...solution };
		const result = server.verifySolution(ticket, answer, context);
		ticket.x = "00".repeat(256);
		ticket.id = "00".repeat(32);
		answer.pi = "00".repeat(256);
		expect(await result).toBe(true);
	});

	test("server configuration and secret are captured at construction", async () => {
		const mutable = {
			...options,
			secret: new Uint8Array(secret),
			consume: () => true,
		};
		const pending = createPowServer(mutable);
		mutable.secret.fill(0);
		mutable.iterations = 1001;
		mutable.consume = () => false;
		const server = await pending;
		expect(await server.verifySolution(challenge, solution, context)).toBe(
			true,
		);
	});

	test("expiry is enforced before verification and after storage awaits", async () => {
		let calls = 0;
		const server = await createPowServer({
			...options,
			consume: () => {
				calls++;
				return true;
			},
		});
		try {
			setSystemTime(new Date(challenge.expiresAt));
			expect(await server.verifySolution(challenge, solution, context)).toBe(
				false,
			);
			setSystemTime(new Date(challenge.issuedAt - 1));
			expect(await server.verifySolution(challenge, solution, context)).toBe(
				false,
			);
		} finally {
			setSystemTime();
		}
		expect(calls).toBe(0);
		const delayedStore = await createPowServer({
			...options,
			consume: async () => {
				setSystemTime(new Date(challenge.expiresAt));
				return true;
			},
		});
		try {
			expect(
				await delayedStore.verifySolution(challenge, solution, context),
			).toBe(false);
		} finally {
			setSystemTime();
		}
	});

	test("storage errors propagate and non-boolean claims fail closed", async () => {
		const broken = await createPowServer({
			...options,
			consume: () => {
				throw new Error("storage unavailable");
			},
		});
		await expect(
			broken.verifySolution(challenge, solution, context),
		).rejects.toThrow("storage unavailable");
		const denied = await createPowServer({ ...options, consume: () => false });
		expect(await denied.verifySolution(challenge, solution, context)).toBe(
			false,
		);
		const wrongType = await createPowServer({
			...options,
			consume: (() => "OK") as unknown as () => boolean,
		});
		expect(await wrongType.verifySolution(challenge, solution, context)).toBe(
			false,
		);
	});

	test("trivial and out-of-group inputs fail even with authentic tickets", async () => {
		const server = await createPowServer({ ...options, consume: () => true });
		for (const x of [0n, 1n, RSA_2048 - 1n, RSA_2048]) {
			const ticket = await sign({
				...challenge,
				x: x.toString(16).padStart(512, "0"),
			});
			expect(await server.verifySolution(ticket, solution, context)).toBe(
				false,
			);
			await expect(solveChallenge(ticket)).rejects.toThrow(
				"invalid challenge input",
			);
		}
	});

	test("malformed and oversized tickets and solutions are rejected", async () => {
		let calls = 0;
		const server = await createPowServer({
			...options,
			consume: () => {
				calls++;
				return true;
			},
		});
		const badTickets: unknown[] = [
			null,
			[],
			"ticket",
			{},
			{ ...challenge, version: 2 },
			{ ...challenge, iterations: NaN },
			{ ...challenge, iterations: Infinity },
			{ ...challenge, iterations: 1000.5 },
			{ ...challenge, iterations: 0 },
			{ ...challenge, issuedAt: -1 },
			{ ...challenge, expiresAt: Number.MAX_SAFE_INTEGER + 1 },
			{ ...challenge, context: "x".repeat(257) },
			{ ...challenge, context: "" },
			{ ...challenge, id: challenge.id.toUpperCase() },
			{ ...challenge, x: "f".repeat(513) },
			{ ...challenge, x: "g".repeat(512) },
			{ ...challenge, mac: "0".repeat(65) },
			{ ...challenge, n: "7" },
			{ ...challenge, nonce: "00".repeat(32) },
		];
		for (const ticket of badTickets) {
			expect(await server.verifySolution(ticket, solution, context)).toBe(
				false,
			);
			await expect(solveChallenge(ticket)).rejects.toThrow();
		}
		for (const answer of [
			null,
			[],
			{},
			{ ...solution, n: "7" },
			{ ...solution, l: "3" },
			{ ...solution, pi: "f".repeat(513) },
			{ ...solution, h: "g".repeat(512) },
			{ ...solution, pi: "00".repeat(256) },
			{ ...solution, h: "00".repeat(256) },
			{ ...solution, h: RSA_2048.toString(16) },
		])
			expect(await server.verifySolution(challenge, answer, context)).toBe(
				false,
			);
		expect(calls).toBe(0);
	});

	test("solver has an independent work cap and fixed-width output", async () => {
		await expect(
			solveChallenge({ ...challenge, iterations: 1_000_001 }),
		).rejects.toThrow("maxIterations");
		await expect(
			solveChallenge(challenge, { maxIterations: Infinity }),
		).rejects.toThrow();
		const answer = await solveChallenge(challenge, { maxIterations: 1000 });
		expect(answer).toEqual(solution);
		expect(Object.keys(answer).sort()).toEqual(["h", "pi"]);
		expect(answer.h).toHaveLength(512);
		expect(answer.pi).toHaveLength(512);
	});

	test("invalid server configuration is rejected", async () => {
		for (const iterations of [0, 999, 1000.5, NaN, Infinity, 10_000_001]) {
			await expect(
				createPowServer({ ...options, iterations, consume: () => true }),
			).rejects.toThrow();
		}
		for (const ttlMs of [0, 999, 1000.5, Infinity, 600_001]) {
			await expect(
				createPowServer({ ...options, ttlMs, consume: () => true }),
			).rejects.toThrow();
		}
		await expect(
			createPowServer({
				...options,
				secret: new Uint8Array(31),
				consume: () => true,
			}),
		).rejects.toThrow();
		await expect(
			createPowServer({ ...options, consume: undefined as never }),
		).rejects.toThrow();
		const server = await createPowServer({ ...options, consume: () => true });
		await expect(server.createChallenge("")).rejects.toThrow();
		await expect(server.createChallenge("a".repeat(257))).rejects.toThrow();
	});
});

describe("in-memory replay store", () => {
	test("retains live claims and fails closed at capacity", () => {
		const store = new InMemoryReplayStore(1);
		const expiresAt = Date.now() + 60_000;
		expect(store.consume("01".repeat(32), expiresAt)).toBe(true);
		expect(store.consume("02".repeat(32), expiresAt)).toBe(false);
		expect(store.consume("01".repeat(32), expiresAt)).toBe(false);
		try {
			setSystemTime(new Date(expiresAt));
			expect(store.consume("02".repeat(32), expiresAt + 1000)).toBe(true);
			expect(store.consume("01".repeat(32), expiresAt)).toBe(false);
		} finally {
			setSystemTime();
		}
	});

	test("a backwards clock cannot resurrect an evicted claim", () => {
		const store = new InMemoryReplayStore(2);
		const start = Date.now();
		const expiresAt = start + 1000;
		expect(store.consume("01".repeat(32), expiresAt)).toBe(true);
		try {
			setSystemTime(new Date(expiresAt));
			expect(store.consume("02".repeat(32), expiresAt + 1000)).toBe(true);
			setSystemTime(new Date(start));
			expect(store.consume("01".repeat(32), expiresAt)).toBe(false);
		} finally {
			setSystemTime();
		}
	});

	test("rejects bad capacity, IDs and expiration", () => {
		for (const capacity of [0, -1, NaN, Infinity, 1.5])
			expect(() => new InMemoryReplayStore(capacity)).toThrow();
		const store = new InMemoryReplayStore();
		expect(store.consume("bad", Date.now() + 1000)).toBe(false);
		expect(store.consume("00".repeat(32), Date.now())).toBe(false);
		expect(store.consume("00".repeat(32), Infinity)).toBe(false);
	});
});

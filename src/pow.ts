import { bigintToFixedBytes, bytesToBigint, gcd } from "./utils.ts";
import {
	deriveChallenge,
	evaluate,
	generateProof,
	RSA_2048,
	verify,
} from "./vdf.ts";

const DOMAIN = "wesolowski-web-pow-rsa2048-v1";
const MIN_ITERATIONS = 1_000;
const MAX_ITERATIONS = 10_000_000;
const MAX_TTL_MS = 600_000;
const encoder = new TextEncoder();

/** Enforce this limit on the HTTP body before parsing a challenge and solution. */
export const MAX_POW_REQUEST_BYTES = 8192;

/** JSON-safe, authenticated server challenge. Version 1 always uses RSA-2048. */
export interface PowChallenge {
	readonly version: 1;
	readonly id: string;
	readonly x: string;
	readonly iterations: number;
	readonly issuedAt: number;
	readonly expiresAt: number;
	readonly context: string;
	readonly mac: string;
}

/** Fixed-width lowercase hexadecimal values; no client-selected parameters. */
export interface PowSolution {
	readonly h: string;
	readonly pi: string;
}

/**
 * Atomically claim an unexpired ID, returning true only for its first use.
 * All verifiers sharing an issuing key must share this store.
 * Retain claimed IDs until expiresAt (Unix milliseconds); never evict live IDs.
 * Storage failures must throw or return false, never grant access.
 */
export type ConsumeChallenge = (
	id: string,
	expiresAt: number,
) => boolean | Promise<boolean>;

export interface PowServerOptions {
	/** At least 32 cryptographically random bytes, kept only on the server. */
	secret: Uint8Array;
	/** Sequential squarings, from 1,000 to 10,000,000. Calibrate on fast clients. */
	iterations: number;
	/** Atomic single-use storage. Required even when tickets are authenticated. */
	consume: ConsumeChallenge;
	/** Challenge lifetime in milliseconds, from 1,000 to 600,000. Default: 60,000. */
	ttlMs?: number;
}

export interface PowServer {
	/** Bind context to the action and, where appropriate, the authenticated session. */
	createChallenge(context: string): Promise<PowChallenge>;
	/**
	 * Verify and consume a solution before granting access.
	 * context must come from the server's expected action, not the submitted ticket.
	 * Malformed, invalid, expired, and replayed submissions return false.
	 * Crypto or storage failures throw; applications must fail closed.
	 */
	verifySolution(
		challenge: unknown,
		solution: unknown,
		context: string,
	): Promise<boolean>;
}

function validInteger(
	value: unknown,
	min: number,
	max: number,
): value is number {
	return (
		typeof value === "number" &&
		Number.isSafeInteger(value) &&
		value >= min &&
		value <= max
	);
}

function validContext(value: unknown): value is string {
	return typeof value === "string" && value.length > 0 && value.length <= 256;
}

function validHex(value: unknown, length: number): value is string {
	return (
		typeof value === "string" &&
		value.length === length &&
		/^[0-9a-f]+$/.test(value)
	);
}

function exactFields(
	value: unknown,
	fields: readonly string[],
): value is Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value))
		return false;
	const keys = Object.keys(value);
	return (
		keys.length === fields.length &&
		fields.every((key) => Object.hasOwn(value, key))
	);
}

function readChallenge(value: unknown): PowChallenge | undefined {
	if (
		!exactFields(value, [
			"version",
			"id",
			"x",
			"iterations",
			"issuedAt",
			"expiresAt",
			"context",
			"mac",
		])
	)
		return;
	const { version, id, x, iterations, issuedAt, expiresAt, context, mac } =
		value;
	if (
		version !== 1 ||
		!validHex(id, 64) ||
		!validHex(x, 512) ||
		!validHex(mac, 64) ||
		!validInteger(iterations, MIN_ITERATIONS, MAX_ITERATIONS) ||
		!validInteger(issuedAt, 0, Number.MAX_SAFE_INTEGER) ||
		!validInteger(expiresAt, 0, Number.MAX_SAFE_INTEGER) ||
		expiresAt - issuedAt < 1000 ||
		expiresAt - issuedAt > MAX_TTL_MS ||
		!validContext(context)
	)
		return;
	return { version, id, x, iterations, issuedAt, expiresAt, context, mac };
}

function readSolution(value: unknown): PowSolution | undefined {
	if (!exactFields(value, ["h", "pi"])) return;
	const { h, pi } = value;
	if (!validHex(h, 512) || !validHex(pi, 512)) return;
	return { h, pi };
}

function ticketBytes(
	challenge: Omit<PowChallenge, "mac">,
): Uint8Array<ArrayBuffer> {
	return encoder.encode(
		JSON.stringify([
			DOMAIN,
			challenge.version,
			challenge.id,
			challenge.x,
			challenge.iterations,
			challenge.issuedAt,
			challenge.expiresAt,
			challenge.context,
		]),
	);
}

function hexBytes(hex: string): Uint8Array<ArrayBuffer> {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++)
		bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return bytes;
}

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join(
		"",
	);
}

function freshInput(): bigint {
	const bytes = new Uint8Array(256);
	while (true) {
		crypto.getRandomValues(bytes);
		const r = bytesToBigint(bytes);
		if (r <= 1n || r >= RSA_2048 || gcd(r, RSA_2048) !== 1n) continue;
		const x = (r * r) % RSA_2048;
		if (x > 1n && x < RSA_2048 - 1n) return x;
	}
}

function nondecreasingClock(): () => number {
	let lastTime = Date.now();
	return () => {
		lastTime = Math.max(lastTime, Date.now());
		return lastTime;
	};
}

function validInput(x: bigint): boolean {
	return x > 1n && x < RSA_2048 - 1n && gcd(x, RSA_2048) === 1n;
}

/**
 * Create a server-only issuer/verifier with authenticated, single-use tickets.
 * Keep the key stable across replicas and restarts, and use shared atomic storage.
 * Rotating the key invalidates outstanding tickets.
 */
export async function createPowServer(
	options: PowServerOptions,
): Promise<PowServer> {
	const { iterations, consume, ttlMs = 60_000 } = options;
	if (
		!(options.secret instanceof Uint8Array) ||
		options.secret.length < 32 ||
		options.secret.length > 1024
	) {
		throw new RangeError("secret must contain 32 to 1024 random bytes");
	}
	if (!validInteger(iterations, MIN_ITERATIONS, MAX_ITERATIONS)) {
		throw new RangeError("iterations must be an integer from 1000 to 10000000");
	}
	if (!validInteger(ttlMs, 1000, MAX_TTL_MS))
		throw new RangeError("ttlMs must be an integer from 1000 to 600000");
	if (typeof consume !== "function")
		throw new TypeError("an atomic consume callback is required");
	const now = nondecreasingClock();
	const key = await crypto.subtle.importKey(
		"raw",
		new Uint8Array(options.secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign", "verify"],
	);

	return {
		async createChallenge(context) {
			if (!validContext(context))
				throw new RangeError("context must contain 1 to 256 characters");
			const issuedAt = now();
			const fields = {
				version: 1 as const,
				id: toHex(crypto.getRandomValues(new Uint8Array(32))),
				x: freshInput().toString(16).padStart(512, "0"),
				iterations,
				issuedAt,
				expiresAt: issuedAt + ttlMs,
				context,
			};
			const mac = await crypto.subtle.sign("HMAC", key, ticketBytes(fields));
			return { ...fields, mac: toHex(new Uint8Array(mac)) };
		},

		async verifySolution(challenge, solution, context) {
			const ticket = readChallenge(challenge);
			const answer = readSolution(solution);
			if (
				!ticket ||
				!answer ||
				!validContext(context) ||
				ticket.context !== context
			)
				return false;
			const currentTime = now();
			if (
				ticket.issuedAt > currentTime ||
				ticket.expiresAt <= currentTime ||
				ticket.iterations !== iterations ||
				ticket.expiresAt - ticket.issuedAt !== ttlMs
			)
				return false;
			if (
				!(await crypto.subtle.verify(
					"HMAC",
					key,
					hexBytes(ticket.mac),
					ticketBytes(ticket),
				))
			)
				return false;

			const x = BigInt(`0x${ticket.x}`);
			const h = BigInt(`0x${answer.h}`);
			const pi = BigInt(`0x${answer.pi}`);
			if (
				!validInput(x) ||
				h <= 0n ||
				h >= RSA_2048 ||
				pi <= 0n ||
				pi >= RSA_2048
			)
				return false;
			const output = { x, h, n: RSA_2048, t: ticket.iterations };
			const nonce = hexBytes(ticket.id);
			const l = await deriveChallenge(output, nonce);
			if (!verify({ ...output, pi, l, nonce })) return false;
			if (ticket.expiresAt <= now()) return false;
			const consumed = await consume(ticket.id, ticket.expiresAt);
			return consumed === true && ticket.expiresAt > now();
		},
	};
}

export interface SolveChallengeOptions {
	/** Refuse more work than this local cap. Default: 1,000,000 squarings. */
	maxIterations?: number;
}

/**
 * Solve a JSON-decoded ticket from your trusted server.
 * The client cannot authenticate its MAC; it enforces a local work limit instead.
 * Evaluation is synchronous CPU work: run this function in a Web Worker.
 */
export async function solveChallenge(
	challenge: unknown,
	options: SolveChallengeOptions = {},
): Promise<PowSolution> {
	const ticket = readChallenge(challenge);
	if (!ticket) throw new TypeError("invalid PoW challenge");
	const maxIterations = options.maxIterations ?? 1_000_000;
	if (!validInteger(maxIterations, MIN_ITERATIONS, MAX_ITERATIONS))
		throw new RangeError("invalid maxIterations");
	if (ticket.iterations > maxIterations)
		throw new RangeError("challenge exceeds maxIterations");
	const x = BigInt(`0x${ticket.x}`);
	if (!validInput(x)) throw new RangeError("invalid challenge input");
	const output = evaluate(x, { n: RSA_2048, t: ticket.iterations });
	const proof = await generateProof(output, hexBytes(ticket.id));
	return {
		h: toHex(bigintToFixedBytes(proof.h, 256)),
		pi: toHex(bigintToFixedBytes(proof.pi, 256)),
	};
}

/**
 * Bounded, atomic replay storage for ONE JavaScript process only.
 * Reuse this instance for every request; restart with a new issuing key.
 * Multiple processes or stable keys across restarts require durable shared storage.
 * A full store rejects new claims rather than evicting live replay protection.
 */
export class InMemoryReplayStore {
	readonly #used = new Map<string, number>();
	readonly #capacity: number;
	readonly #now = nondecreasingClock();

	constructor(capacity = 10_000) {
		if (!validInteger(capacity, 1, 1_000_000))
			throw new RangeError("invalid replay store capacity");
		this.#capacity = capacity;
	}

	readonly consume: ConsumeChallenge = (id, expiresAt) => {
		const now = this.#now();
		if (
			!validHex(id, 64) ||
			!validInteger(expiresAt, now + 1, now + MAX_TTL_MS)
		)
			return false;
		for (const [usedId, expiry] of this.#used) {
			if (expiry <= now) this.#used.delete(usedId);
		}
		if (this.#used.has(id) || this.#used.size >= this.#capacity) return false;
		this.#used.set(id, expiresAt);
		return true;
	};
}

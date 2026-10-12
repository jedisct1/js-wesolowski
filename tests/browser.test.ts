import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { evaluate, generateProof, RSA_2048 } from "../src/vdf.ts";

let buildDirectory: string;
let utilsModule: string;
let vdfModule: string;
let expectedProof: { h: string; pi: string; l: string };

beforeAll(async () => {
	const directory = new URL("../tmp/browser-pow/", import.meta.url);
	await mkdir(directory, { recursive: true });
	buildDirectory = await mkdtemp(fileURLToPath(new URL("bundle-", directory)));
	const build = await Bun.build({
		entrypoints: [
			fileURLToPath(new URL("../src/utils.ts", import.meta.url)),
			fileURLToPath(new URL("../src/vdf.ts", import.meta.url)),
		],
		target: "browser",
		format: "esm",
		outdir: buildDirectory,
	});
	expect(build.success).toBe(true);
	for (const output of build.outputs) {
		if (output.path.endsWith("/utils.js")) utilsModule = output.path;
		if (output.path.endsWith("/vdf.js")) vdfModule = output.path;
	}
	expect(utilsModule).toBeDefined();
	expect(vdfModule).toBeDefined();
	const nonce = Uint8Array.from({ length: 32 }, (_, i) => i);
	const proof = await generateProof(
		evaluate(2n, { n: RSA_2048, t: 1024 }),
		nonce,
	);
	expect(proof.pi).toBeGreaterThan(1n);
	expectedProof = {
		h: proof.h.toString(),
		pi: proof.pi.toString(),
		l: proof.l.toString(),
	};
});

afterAll(async () => {
	if (buildDirectory)
		await rm(buildDirectory, { recursive: true, force: true });
});

const modes = [
	"native hex without Buffer",
	"portable fallback",
	"Buffer fallback",
];

const vectors = [
	0n,
	1n,
	15n,
	255n,
	256n,
	0xabcn,
	0x123456789abcdef0n,
	RSA_2048,
	(1n << 4096n) - 1n,
].map((value) => {
	let hex = value.toString(16);
	if (hex.length % 2) hex = `0${hex}`;
	return [value.toString(), Array.from(Buffer.from(hex, "hex"))];
});

describe("browser compatibility", () => {
	test.each(modes)(
		"%s",
		async (mode) => {
			const source = `
			${mode !== "Buffer fallback" ? "globalThis.Buffer = undefined;" : ""}
			${mode !== "native hex without Buffer" ? "Uint8Array.fromHex = undefined; Uint8Array.prototype.toHex = undefined;" : ""}
			const { bigintToBytes, bigintToFixedBytes, bytesToBigint } = await import(${JSON.stringify(utilsModule)});
			const { evaluate, generateProof, verifyWithChallenge, RSA_2048 } = await import(${JSON.stringify(vdfModule)});
			function assert(condition, message) {
				if (!condition) throw new Error(message);
			}
			function assertRangeError(fn) {
				try { fn(); } catch (error) {
					assert(error instanceof RangeError, "expected RangeError");
					return;
				}
				throw new Error("expected a rejected conversion");
			}
			for (const [text, expected] of ${JSON.stringify(vectors)}) {
				const value = BigInt(text);
				const bytes = bigintToBytes(value);
				assert(bytes.constructor === Uint8Array, "plain Uint8Array result");
				assert(JSON.stringify(Array.from(bytes)) === JSON.stringify(expected), "big-endian bytes");
				assert(bytesToBigint(bytes) === value, "bigint roundtrip");
			}
			assert(bytesToBigint(new Uint8Array()) === 0n, "empty bytes");
			assert(bytesToBigint(new Uint8Array([0, 0, 1])) === 1n, "leading zero bytes");
			const backing = new Uint8Array([99, 0, 1, 2, 88]);
			assert(bytesToBigint(backing.subarray(1, 4)) === 258n, "subarray boundaries");
			assert(backing.join() === "99,0,1,2,88", "input is not mutated");
			const allBytes = Uint8Array.from({ length: 256 }, (_, i) => i);
			const padded = bigintToFixedBytes(bytesToBigint(allBytes), 256);
			assert(padded.every((value, i) => value === i), "all byte values");
			assert(bigintToFixedBytes(0xabcn, 4).join() === "0,0,10,188", "left padding");
			assert(bigintToFixedBytes(0n, 4).join() === "0,0,0,0", "zero padding");
			assertRangeError(() => bigintToFixedBytes(256n, 1));
			assertRangeError(() => bigintToFixedBytes(0n, 0));
			assertRangeError(() => bigintToBytes(-1n));
			assertRangeError(() => bigintToFixedBytes(-1n, 4));
			const nonce = Uint8Array.from({ length: 32 }, (_, i) => i);
			const output = evaluate(2n, { n: RSA_2048, t: 1024 });
			const proof = await generateProof(output, nonce);
			assert(proof.pi > 1n, "nontrivial RSA proof");
			assert(await verifyWithChallenge(proof), "valid proof");
			assert(!await verifyWithChallenge({ ...proof, pi: 1n }), "tampered proof");
			assert(!await verifyWithChallenge({ ...proof, h: (proof.h + 1n) % proof.n }), "tampered output");
			const changedNonce = nonce.slice();
			changedNonce[0] ^= 1;
			assert(!await verifyWithChallenge({ ...proof, nonce: changedNonce }), "tampered nonce");
			const randomProof = await generateProof(output);
			assert(randomProof.nonce.length === 32 && await verifyWithChallenge(randomProof), "Web Crypto nonce");
			console.log(JSON.stringify({ h: proof.h.toString(), pi: proof.pi.toString(), l: proof.l.toString() }));
		`;
			const child = Bun.spawn([process.execPath, "--eval", source], {
				stdout: "pipe",
				stderr: "pipe",
			});
			const [exitCode, stdout, stderr] = await Promise.all([
				child.exited,
				new Response(child.stdout).text(),
				new Response(child.stderr).text(),
			]);
			expect(stderr).toBe("");
			expect(exitCode).toBe(0);
			expect(JSON.parse(stdout)).toEqual(expectedProof);
		},
		30_000,
	);
});

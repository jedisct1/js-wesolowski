import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";
import { solveChallenge } from "../src/pow.ts";

test("website example gates access, rejects replay, and bounds streamed bodies", async () => {
	const reservation = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch: () => new Response(),
	});
	const port = reservation.port!;
	await reservation.stop(true);
	const child = Bun.spawn(
		[
			process.execPath,
			"run",
			fileURLToPath(new URL("../examples/pow-server.ts", import.meta.url)),
		],
		{
			env: { ...process.env, PORT: String(port) },
			stdout: "pipe",
			stderr: "pipe",
		},
	);
	const errors = new Response(child.stderr).text();
	try {
		const reader = child.stdout.getReader();
		let startup = "";
		try {
			while (!startup.includes("PoW demo:")) {
				const chunk = await reader.read();
				if (chunk.done)
					throw new Error("Example server exited before listening");
				startup += new TextDecoder().decode(chunk.value);
			}
		} finally {
			reader.releaseLock();
		}
		const base = `http://127.0.0.1:${port}`;
		const page = await fetch(base);
		expect(page.status).toBe(200);
		expect(page.headers.get("cache-control")).toBe("no-store");
		expect(await page.text()).toContain('new Worker("/pow-worker.js"');
		const worker = await fetch(`${base}/pow-worker.js`);
		expect(worker.status).toBe(200);
		expect(worker.headers.get("content-type")).toContain("javascript");
		const challenge = await (await fetch(`${base}/challenge`)).json();
		const solution = await solveChallenge(challenge);
		const submit = (body: unknown) =>
			fetch(`${base}/protected`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
			});
		const concurrent = await Promise.all([
			submit({ challenge, solution }),
			submit({ challenge, solution }),
		]);
		expect(concurrent.map((response) => response.status).sort()).toEqual([
			200, 403,
		]);
		const accepted = concurrent.find((response) => response.status === 200)!;
		expect(((await accepted.json()) as { content: string }).content).toContain(
			"Welcome!",
		);
		expect((await submit({ challenge, solution })).status).toBe(403);
		const other = await (await fetch(`${base}/challenge`)).json();
		expect((await submit({ challenge: other, solution })).status).toBe(403);
		expect((await fetch(`${base}/protected`)).status).toBe(405);
		expect(
			(await fetch(`${base}/protected`, { method: "POST", body: "{}" })).status,
		).toBe(415);
		expect(
			(
				await fetch(`${base}/protected`, {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: "{",
				})
			).status,
		).toBe(400);
		const oversized = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new Uint8Array(4096).fill(32));
				controller.enqueue(new Uint8Array(4097).fill(32));
				controller.close();
			},
		});
		expect(
			(
				await fetch(`${base}/protected`, {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: oversized,
				})
			).status,
		).toBe(413);
	} finally {
		child.kill();
		await child.exited;
		expect(await errors).toBe("");
	}
}, 30_000);

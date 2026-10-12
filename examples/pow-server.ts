import {
	createPowServer,
	InMemoryReplayStore,
	MAX_POW_REQUEST_BYTES,
} from "../src/pow.ts";

const portText = process.env.PORT ?? "3000";
const port = Number(portText);
if (
	!/^\d+$/.test(portText) ||
	!Number.isSafeInteger(port) ||
	port < 1 ||
	port > 65535
) {
	throw new Error("PORT must be an integer from 1 to 65535");
}

const actionContext = "pow-demo:POST:/protected:v1";
const replayStore = new InMemoryReplayStore();
const pow = await createPowServer({
	secret: crypto.getRandomValues(new Uint8Array(32)),
	iterations: 100_000,
	consume: replayStore.consume,
});

const build = await Bun.build({
	entrypoints: [`${import.meta.dir}/pow-worker.ts`],
	target: "browser",
	format: "esm",
});
if (!build.success || build.outputs.length !== 1) {
	throw new AggregateError(build.logs, "Could not bundle the PoW worker");
}
const workerSource = await build.outputs[0]!.text();
const html = await Bun.file(new URL("./pow.html", import.meta.url)).text();
const headers = {
	"Cache-Control": "no-store",
	"X-Content-Type-Options": "nosniff",
	"Referrer-Policy": "no-referrer",
};

class BodyError extends Error {
	constructor(
		readonly status: number,
		message: string,
	) {
		super(message);
	}
}

async function readJson(request: Request): Promise<unknown> {
	const reader = request.body?.getReader();
	if (!reader) throw new BodyError(400, "Expected a JSON body.");
	const chunks: Uint8Array[] = [];
	let size = 0;
	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) break;
			size += value.byteLength;
			if (size > MAX_POW_REQUEST_BYTES) {
				void reader.cancel().catch(() => {});
				throw new BodyError(413, "Request body exceeds 8192 bytes.");
			}
			chunks.push(value);
		}
	} catch (error) {
		if (error instanceof BodyError) throw error;
		throw new BodyError(400, "Could not read the request body.");
	} finally {
		reader.releaseLock();
	}
	const bytes = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	try {
		return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
	} catch {
		throw new BodyError(400, "Malformed JSON body.");
	}
}

function json(body: unknown, status = 200): Response {
	return Response.json(body, { status, headers });
}

const server = Bun.serve({
	hostname: "127.0.0.1",
	port,
	maxRequestBodySize: MAX_POW_REQUEST_BYTES,
	async fetch(request) {
		const path = new URL(request.url).pathname;
		const method = path === "/protected" ? "POST" : "GET";
		if (!["/", "/pow-worker.js", "/challenge", "/protected"].includes(path)) {
			return json({ error: "Not found." }, 404);
		}
		if (request.method !== method) {
			return new Response("Method not allowed.", {
				status: 405,
				headers: { ...headers, Allow: method },
			});
		}
		try {
			if (path === "/") {
				return new Response(html, {
					headers: { ...headers, "Content-Type": "text/html; charset=utf-8" },
				});
			}
			if (path === "/pow-worker.js") {
				return new Response(workerSource, {
					headers: {
						...headers,
						"Content-Type": "text/javascript; charset=utf-8",
					},
				});
			}
			if (path === "/challenge") {
				return json(await pow.createChallenge(actionContext));
			}
			if (
				request.headers
					.get("Content-Type")
					?.split(";")[0]
					?.trim()
					.toLowerCase() !== "application/json"
			) {
				return json({ error: "Use Content-Type: application/json." }, 415);
			}
			const body = await readJson(request);
			if (typeof body !== "object" || body === null || Array.isArray(body)) {
				return json({ error: "Invalid proof or ticket." }, 403);
			}
			const { challenge, solution } = body as Record<string, unknown>;
			if (!(await pow.verifySolution(challenge, solution, actionContext))) {
				return json(
					{
						error:
							"Invalid, expired, or already used proof. Request a new challenge.",
					},
					403,
				);
			}
			return json({
				content:
					"Welcome! This protected content was returned only after your proof was verified and its ticket consumed.",
			});
		} catch (error) {
			if (error instanceof BodyError)
				return json({ error: error.message }, error.status);
			return json(
				{ error: "Proof service unavailable. Access was not granted." },
				503,
			);
		}
	},
});

console.log(`PoW demo: http://127.0.0.1:${server.port}`);
console.log(
	"Single-process demo: ephemeral key, in-memory replay storage, no rate limiting.",
);

import { solveChallenge } from "../src/pow.ts";

const worker = globalThis as unknown as {
	onmessage: ((event: MessageEvent<unknown>) => void) | null;
	postMessage(message: unknown): void;
	close(): void;
};

worker.onmessage = async (event: MessageEvent<unknown>) => {
	worker.onmessage = null;
	try {
		const solution = await solveChallenge(event.data, {
			maxIterations: 1_000_000,
		});
		worker.postMessage({ solution });
	} catch {
		worker.postMessage({
			error: "Could not solve this challenge. Request a new one.",
		});
	} finally {
		worker.close();
	}
};

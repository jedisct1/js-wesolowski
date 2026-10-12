# Browser proof-of-work example

From the repository root, with Bun 1.3.11 or newer:

```sh
bun run examples/pow-server.ts
```

Open <http://127.0.0.1:3000> and choose **Get protected content**.
No extra dependencies or separate build step are needed.
The server bundles `pow-worker.ts` for the browser in memory at startup.
To use another port:

```sh
PORT=3001 bun run examples/pow-server.ts
```

`PORT` must be an integer from 1 to 65535.
The server listens only on `127.0.0.1`; stop it with Ctrl-C.

## How access works

1. The browser fetches a JSON ticket from `GET /challenge`.
2. A Web Worker calls `solveChallenge`, leaving the page responsive.
   Canceling, leaving the page, completing the proof, or encountering an error terminates the worker.
3. The browser posts `{ challenge, solution }` as JSON to `POST /protected`.
4. The server calls `verifySolution` with its own fixed action context, not a context supplied by the client.
   Only after verification and atomic replay consumption does it return the protected content in that response.

There is no reusable access token, unlocked public URL, or client-side access flag.
Each access requires a fresh ticket.
Canceling a submitted request does not undo server-side ticket consumption.

The example uses RSA-2048, 100,000 iterations, and the API's 60-second ticket lifetime.
The worker refuses challenges above 1,000,000 iterations.
These settings illustrate the flow; they are not a promised delay across different devices.

The server bounds streamed request bodies at 8,192 bytes before decoding JSON, including requests without `Content-Length`.
Oversized bodies get HTTP 413, malformed JSON gets 400, and invalid, expired, or replayed proofs get 403.
Crypto or replay-storage exceptions return 503 without granting access.
Responses use `Cache-Control: no-store`, and the UI displays returned text with `textContent`.

## Limits before deployment

This is deliberately a **single-process local demo**.
One `InMemoryReplayStore` is reused for all requests, and a fresh random signing key is created at startup.
Restarting invalidates outstanding tickets.
The store rejects new claims if its bounded capacity is full; it never evicts live replay protection to grant access.

Production replicas need a securely managed issuing key and shared, atomic replay storage that retains consumed IDs through expiration.
A stable key across restarts also requires durable replay storage.
Storage failures must deny access.
Bind tickets to the actual server-side action and, where appropriate, an authenticated session and request parameters.
Keep the existing application's authentication, authorization, and CSRF protections.

This example has no rate limiting or global verification-concurrency limit.
Add request timeouts, challenge-issuance and verification rate limits, concurrency limits, and traffic controls at the server or reverse proxy before exposing a service.
Use HTTPS in production, calibrate work on fast clients, and consider the cost to mobile devices and users who cannot run the worker.

A VDF imposes sequential work on each attempt, not on an attacker's aggregate traffic.
Attackers can solve separate challenges in parallel, and issuing tickets and checking invalid submissions still cost server resources.
This is not a CAPTCHA, proof of a human, or aggregate denial-of-service prevention.

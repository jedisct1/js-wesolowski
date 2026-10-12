import {
	gcd,
	modpow,
	modpowProduct,
	bigintByteLength,
	bigintBitLength,
	bigintToFixedBytes,
	bytesToBigint,
	concatBytes,
	u64be,
	MontgomeryReducer,
} from "./utils.ts";
import { isPrime, nextPrime } from "./prime.ts";

/**
 * RSA-2048 modulus from the RSA Factoring Challenge.
 * This is a well-known modulus where the factorization is unknown.
 */
export const RSA_2048 =
	25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357n;

/**
 * RSA-3072 modulus generated deterministically from seed "wesolowski-vdf-3072-v1".
 * Product of two 1536-bit primes derived via SHA-512 expansion of the seed.
 */
export const RSA_3072 =
	3015017089231152757690960192819102043239114796373510848429903864432127926621011048902548224914569976574804545802968225392515796580594427309749119888690514520697735227809080892639645726606101685161543130533709224983923499813299534038323830120529164922439502839581694290284582033382579949482144483502720609219537823773807003486475077998035830574897791371155216308955087907581855160547723014498258992595638871429884236335782312503122137811385209002498762063575873159567710402632512148958867479020086529560547316399102161601294979708849478217224852074530699599634015563903219513047529247971412842419113291879987671441984672878552236993930476157095066037788836046668352516519753931267560471531031825708279999678181842184116371633187398287164131540429506469512602889505388574166070224051019663670261449037721581090162255144436879425655099190029928032159780455118934994948531030466424988709057802054494434743489026933108953509721187n;

/**
 * RSA-4096 modulus generated deterministically from seed "wesolowski-vdf-4096-v1".
 * Product of two 2048-bit primes derived via SHA-512 expansion of the seed.
 */
export const RSA_4096 =
	747352962051197730297934919296234225189963654905354427935353846101556895653541386541113520324263294236545904951060839962240274328375769020274431343912159134032165179555313439967918389676450595794483961040941009764122804794391046181942378647240304779972800690260262458348432539960153442657440901219540972943438653104032458070568153835275543015109580808966986224704918221024659890631684764229276547856850956248069577074873655045641411730285176021174124881403213574051977133606281732412418110713517515403558206281426502307580805475595646318182131891740149180223766312249910746627476702983991742718162876076881178303622511590593201630576134594272015989973633963594696486662570772886452272875842074410973837076866917833535886485424053178508915192831696893924147315437442669203873331664056119890477640884789110398626309285007167528107151236086156213498812507448284884702425573571668426362484661294563894216561407502197042527165655552237164601552270513010824469002566905851820787653065990471601308759319433849706433417940795470233138004510961817143010200050242333170912109749939932325818168759208959845084239707593225093832222693592214393944838071322068559847352433869357261322929618870704385679303841709580866230005780921498919331589072271n;

const precomputedMontgomery = new Map(
	[RSA_2048, RSA_3072, RSA_4096].map((n) => [n, new MontgomeryReducer(n)]),
);

export interface VDFParams {
	/** RSA modulus n */
	n: bigint;
	/** Time parameter (number of sequential squarings) */
	t: number;
}

export interface VDFOutput {
	/** Input value x */
	x: bigint;
	/** Output value h = x^(2^t) mod n */
	h: bigint;
	/** Time parameter */
	t: number;
	/** RSA modulus */
	n: bigint;
}

export interface VDFProof extends VDFOutput {
	/** Proof π */
	pi: bigint;
	/** Challenge prime l */
	l: bigint;
	/** Nonce used to derive l */
	nonce: Uint8Array;
}

const MONTGOMERY_THRESHOLD_T = 1000;
const MONTGOMERY_THRESHOLD_N_BITS = 1024;
const PROOF_DIRECT_EXPONENT_LIMIT_T = 1_000_000;
const PROOF_CHECKPOINT_LIMIT = 1024;

interface ProofCheckpoints {
	x: bigint;
	n: bigint;
	t: number;
	powers: bigint[];
	stride: number;
	mont: MontgomeryReducer;
}

const proofCheckpoints = new WeakMap<VDFOutput, ProofCheckpoints>();

const CHALLENGE_TAG = new TextEncoder().encode("wesolowski-v1");
const CHALLENGE_PRIME_CACHE_LIMIT = 128;

const challengeCache = new Map<bigint, bigint>();
const challengePrimeCache = new Set<bigint>();
const montgomeryCache = new Map<bigint, MontgomeryReducer>();

function getMontgomeryReducer(n: bigint): MontgomeryReducer {
	let reducer = precomputedMontgomery.get(n);
	if (reducer) return reducer;

	reducer = montgomeryCache.get(n);
	if (!reducer) {
		reducer = new MontgomeryReducer(n);
		if (montgomeryCache.size < 10) {
			montgomeryCache.set(n, reducer);
		}
	}
	return reducer;
}

function shouldUseMontgomery(n: bigint, t: number): boolean {
	if (precomputedMontgomery.has(n)) {
		return t >= 100;
	}
	if (t < MONTGOMERY_THRESHOLD_T) {
		return false;
	}
	if ((n & 1n) === 0n) {
		return false;
	}
	const nBits = bigintByteLength(n) * 8;
	return nBits >= MONTGOMERY_THRESHOLD_N_BITS;
}

/**
 * Evaluate the VDF: compute h = x^(2^t) mod n.
 *
 * This requires t sequential squarings and cannot be parallelized.
 * The computation time grows linearly with t.
 * RSA-sized evaluations with 1,000 <= t <= 1,000,000 retain up to 1,024
 * intermediate powers while the returned object is alive to accelerate proving.
 *
 * @param x - Input value (must be coprime to n)
 * @param params - VDF parameters (n, t)
 * @returns VDF output containing x, h, t, n
 */
export function evaluate(x: bigint, params: VDFParams): VDFOutput {
	const { n, t } = params;

	if (x <= 0n || x >= n) {
		throw new RangeError("x must be in range (0, n)");
	}
	if (gcd(x, n) !== 1n) {
		throw new Error("x must be coprime to n");
	}
	if (t <= 0) {
		throw new RangeError("t must be positive");
	}

	if (shouldUseMontgomery(n, t)) {
		const mont = getMontgomeryReducer(n);
		const rMask = mont.rMask;
		const nPrime = mont.nPrime;
		const rBits = mont.rBitsBigint;
		const modN = mont.n;

		const powers: bigint[] | undefined =
			Number.isSafeInteger(t) && t >= 1000 && t <= PROOF_DIRECT_EXPONENT_LIMIT_T
				? []
				: undefined;
		const stride = powers
			? Math.max(16, Math.ceil(t / PROOF_CHECKPOINT_LIMIT / 4) * 4)
			: t;
		let h = mont.toMontgomery(x);
		for (let start = 0; start < t; start += stride) {
			powers?.push(h);
			const end = Math.min(start + stride, t);
			for (let i = start; i < end; i++) {
				const prod = h * h;
				const m = ((prod & rMask) * nPrime) & rMask;
				const u = (prod + m * modN) >> rBits;
				h = u >= modN ? u - modN : u;
			}
		}
		const output = { x, h: mont.fromMontgomery(h), t, n };
		if (powers) proofCheckpoints.set(output, { x, n, t, powers, stride, mont });
		return output;
	}

	let h = x;
	for (let i = 0; i < t; i++) {
		h = (h * h) % n;
	}

	return { x, h, t, n };
}

/**
 * Derive the challenge prime l using Fiat-Shamir transform.
 *
 * The challenge is derived deterministically from SHA-512 hash of the
 * full transcript (g, h, t, n, nonce), then incremented until prime.
 *
 * @param output - VDF output
 * @param nonce - 32-byte random nonce
 * @returns Challenge prime l
 */
export async function deriveChallenge(
	output: VDFOutput,
	nonce: Uint8Array,
): Promise<bigint> {
	const { x, h, t, n } = output;

	if (nonce.length !== 32) {
		throw new RangeError("nonce must be 32 bytes");
	}

	const nLen = bigintByteLength(n);

	const payload = concatBytes(
		CHALLENGE_TAG,
		bigintToFixedBytes(x, nLen),
		bigintToFixedBytes(h, nLen),
		u64be(BigInt(t)),
		bigintToFixedBytes(n, nLen),
		nonce,
	);

	const hash = await crypto.subtle.digest(
		"SHA-512",
		payload as Uint8Array<ArrayBuffer>,
	);

	const hashBigint = bytesToBigint(new Uint8Array(hash));
	const cachedChallenge = challengeCache.get(hashBigint);
	if (cachedChallenge !== undefined) {
		return cachedChallenge;
	}

	const challenge = nextPrime(hashBigint);
	if (challengeCache.size < CHALLENGE_PRIME_CACHE_LIMIT) {
		challengeCache.set(hashBigint, challenge);
		challengePrimeCache.add(challenge);
	}
	return challenge;
}

function proveWithCheckpoints(
	checkpoints: ProofCheckpoints,
	q: bigint,
): bigint {
	const { powers, stride, mont } = checkpoints;
	const hex = q.toString(16);
	const digits = stride / 4;
	const one = mont.toMontgomery(1n);
	let result = one;

	for (let window = digits - 1; window >= 0; window--) {
		for (let j = 0; j < 4; j++) result = mont.square(result);
		const buckets = new Array<bigint | undefined>(16);
		for (let i = 0; i < powers.length; i++) {
			const index = hex.length - 1 - i * digits - window;
			if (index < 0) break;
			const code = hex.charCodeAt(index);
			const digit = code > 57 ? code - 87 : code - 48;
			if (digit !== 0) {
				const bucket = buckets[digit];
				buckets[digit] =
					bucket === undefined ? powers[i]! : mont.multiply(bucket, powers[i]!);
			}
		}

		// Descending products give each bucket its digit as an exponent.
		let running = one;
		for (let digit = 15; digit > 0; digit--) {
			const bucket = buckets[digit];
			if (bucket !== undefined) running = mont.multiply(running, bucket);
			result = mont.multiply(result, running);
		}
	}
	return mont.fromMontgomery(result);
}

/**
 * Generate a Wesolowski proof for a VDF output.
 *
 * The proof π = x^⌊2^t / l⌋ mod n enables efficient verification.
 * Reuses evaluation checkpoints when available, otherwise computes
 * the exponent directly or uses streaming long division for very large t.
 *
 * @param output - VDF output to prove
 * @param l - Challenge prime from verifier
 * @returns Proof value π
 */
export function prove(output: VDFOutput, l: bigint): bigint {
	const { x, t, n } = output;

	if (l > 0n && t < bigintBitLength(l) - 1) {
		return 1n;
	}
	if (l > 0n && t <= PROOF_DIRECT_EXPONENT_LIMIT_T) {
		const q = (1n << BigInt(t)) / l;
		const checkpoints = proofCheckpoints.get(output);
		if (
			l > 1n &&
			checkpoints &&
			checkpoints.x === x &&
			checkpoints.n === n &&
			checkpoints.t === t
		) {
			return proveWithCheckpoints(checkpoints, q);
		}
		return modpow(x, q, n);
	}

	if (l === 1n) return evaluate(x, { n, t }).h;

	if (shouldUseMontgomery(n, t)) {
		const mont = getMontgomeryReducer(n);
		const rMask = mont.rMask;
		const nPrime = mont.nPrime;
		const rBits = mont.rBitsBigint;
		const modN = mont.n;

		const xMont = mont.toMontgomery(x);
		let pi = mont.toMontgomery(1n);
		let r = 1n;

		for (let i = 0; i < t; i++) {
			let prod = pi * pi;
			let m = ((prod & rMask) * nPrime) & rMask;
			let u = (prod + m * modN) >> rBits;
			pi = u >= modN ? u - modN : u;

			const r2 = r << 1n;
			if (r2 >= l) {
				r = r2 - l;
				prod = pi * xMont;
				m = ((prod & rMask) * nPrime) & rMask;
				u = (prod + m * modN) >> rBits;
				pi = u >= modN ? u - modN : u;
			} else {
				r = r2;
			}
		}

		return mont.fromMontgomery(pi);
	}

	let pi = 1n;
	let r = 1n;

	for (let i = 0; i < t; i++) {
		pi = (pi * pi) % n;

		const r2 = r << 1n;
		if (r2 >= l) {
			r = r2 - l;
			pi = (pi * x) % n;
		} else {
			r = r2;
		}
	}

	return pi;
}

/**
 * Generate a complete VDF proof including challenge derivation.
 *
 * @param output - VDF output to prove
 * @param nonce - Optional 32-byte nonce (generated randomly if not provided)
 * @returns Complete VDF proof
 */
export async function generateProof(
	output: VDFOutput,
	nonce?: Uint8Array,
): Promise<VDFProof> {
	if (!nonce) {
		nonce = new Uint8Array(32);
		crypto.getRandomValues(nonce);
	}

	const l = await deriveChallenge(output, nonce);
	const pi = prove(output, l);

	return {
		...output,
		pi,
		l,
		nonce,
	};
}

/**
 * Verify a Wesolowski VDF proof.
 *
 * Checks that π^l · x^r ≡ h (mod n) where r = 2^t mod l.
 * Verification requires only O(log t) exponentiations.
 *
 * @param proof - The proof to verify
 * @returns true if the proof is valid
 */
function verifyProofEquation(
	proof: VDFProof,
	challengeAlreadyVerified: boolean,
): boolean {
	const { x, h, t, n, pi, l } = proof;

	if (pi <= 0n || pi >= n) {
		return false;
	}
	if (x <= 0n || x >= n) {
		return false;
	}
	if (gcd(x, n) !== 1n) {
		return false;
	}
	if (
		l <= 2n ||
		(!challengeAlreadyVerified && !challengePrimeCache.has(l) && !isPrime(l))
	) {
		return false;
	}

	const r = modpow(2n, BigInt(t), l);
	const expected = modpowProduct(pi, l, x, r, n);
	return expected === h;
}

export function verify(proof: VDFProof): boolean {
	return verifyProofEquation(proof, false);
}

/**
 * Full verification including challenge re-derivation.
 *
 * Re-derives the challenge prime from the proof transcript and verifies
 * both the challenge derivation and the proof equation.
 *
 * @param proof - The proof to verify
 * @returns true if the proof is valid
 */
export async function verifyWithChallenge(proof: VDFProof): Promise<boolean> {
	const { x, h, t, n, nonce } = proof;

	// Re-derive the challenge
	const expectedL = await deriveChallenge({ x, h, t, n }, nonce);

	if (expectedL !== proof.l) {
		return false;
	}

	return verifyProofEquation(proof, true);
}

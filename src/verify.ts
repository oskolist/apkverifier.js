/**
 * `verifyApk` orchestrator.
 *
 * Runs the ZIP/EOCD parse, locates the APK signing block (v2/v3), and runs the
 * v1 (JAR), v2, and v3 verifiers. The result reports per-scheme status plus
 * aggregate `verified` / `authorVerified` flags.
 */
import { getZipSections, ZipSections } from "./internal/zip.js";
import { findSigningBlock, findChunk, V2_BLOCK_ID, V3_BLOCK_ID } from "./internal/apk-signature-block.js";
import { verifyV1 } from "./internal/v1.js";
import { verifyV2 } from "./internal/v2.js";
import { verifyV3 } from "./internal/v3.js";
import { VerificationResult, VerifyApkOptions } from "./types.js";

function emptyScheme(): VerificationResult["schemes"]["v1"] {
	return { present: false, passed: false, signers: [], errors: [] };
}

function normalizeHex(s: string): string {
	return s.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
}

export async function verifyApk(apk: Uint8Array, opts: VerifyApkOptions = {}): Promise<VerificationResult> {
	// 1) ZIP structure (central directory + EOCD).
	let sections: ZipSections;
	try {
		sections = getZipSections(apk);
	} catch (e) {
		return {
			verified: false,
			schemes: { v1: emptyScheme(), v2: emptyScheme(), v3: emptyScheme() },
			signerCertSha256: [],
			authorVerified: false,
			error: `bad ZIP: ${(e as Error).message}`,
		};
	}
	const { cdOff, eocdOff, entries } = sections;

	// 2) APK signing block (v2/v3).
	const block = findSigningBlock(apk, cdOff);

	// 3) Run all three schemes in parallel (each is independent & async).
	const v1P = verifyV1(apk, entries);
	let v2P: Promise<ReturnType<typeof emptyScheme>>;
	let v3P: Promise<ReturnType<typeof emptyScheme>>;
	if (block) {
		const v2chunk = findChunk(block.chunks, V2_BLOCK_ID);
		const v3chunk = findChunk(block.chunks, V3_BLOCK_ID);
		v2P = v2chunk
			? verifyV2(apk, v2chunk.data, block.blockStart, cdOff, eocdOff)
			: Promise.resolve(emptyScheme());
		v3P = v3chunk
			? verifyV3(apk, v3chunk.data, block.blockStart, cdOff, eocdOff)
			: Promise.resolve(emptyScheme());
	} else {
		v2P = Promise.resolve(emptyScheme());
		v3P = Promise.resolve(emptyScheme());
	}

	const [v1, v2, v3] = await Promise.all([v1P, v2P, v3P]);

	// Deduplicated signer cert SHA-256 across verified schemes.
	const certs = dedupe(
		[...v1.signers, ...v2.signers, ...v3.signers]
			.filter((s) => s.certSha256)
			.map((s) => s.certSha256.toLowerCase()),
	);

	const verified = v1.passed || v2.passed || v3.passed;

	// Author matching.
	let authorVerified = verified; // a verified APK is signed by *some* signer
	if (opts.expectedCertSha256) {
		const expected = normalizeHex(opts.expectedCertSha256);
		authorVerified = verified && certs.includes(expected);
	}
	if (opts.referenceApk) {
		const refCerts = (await verifyApk(opts.referenceApk)).signerCertSha256;
		authorVerified = verified && refCerts.some((c) => certs.includes(c.toLowerCase()));
	}

	const allErrors = [...v1.errors, ...v2.errors, ...v3.errors];
	return {
		verified,
		schemes: { v1, v2, v3 },
		signerCertSha256: certs,
		authorVerified,
		error: allErrors.length ? allErrors.join("; ") : undefined,
	};
}

function dedupe<T>(arr: T[]): T[] {
	const out: T[] = [];
	for (const x of arr) if (!out.includes(x)) out.push(x);
	return out;
}

// Re-export so consumers can `import { verifyApk }` from the package root.
export type { VerificationResult, VerifyApkOptions };

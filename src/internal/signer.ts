/**
 * Shared parsing of an APK Signature Scheme v2/v3 *signer block* and its
 * *signed data*.
 *
 * Both v2 and v3 chunks contain a length-prefixed SEQUENCE of length-prefixed
 * signer blocks. Each signer block is:
 *
 *   -- v2 --
 *   [ u32 len ][ signedDataBytes ]
 *   [ u32 len ][ signatures ]
 *   [ u32 len ][ publicKey (SPKI) ]
 *
 *   -- v3 --
 *   [ u32 len ][ signedDataBytes ]
 *   [ u32     ][ minSdkVersion ]
 *   [ u32     ][ maxSdkVersion ]
 *   [ u32 len ][ signatures ]
 *   [ u32 len ][ publicKey (SPKI) ]
 *
 * signedDataBytes layout:
 *
 *   v2: [u32 len][digests][u32 len][certs][u32 len][addlAttrs][u32 0][empty]
 *   v3: [u32 len][digests][u32 len][certs][u32 minSdk][u32 maxSdk][u32 len][addlAttrs]
 *
 * where `digests` / `signatures` are sequences of
 *   [ u32 entryLen ][ [ u32 sigAlgId ][ u32 len ][ bytes ] ]
 * and `certs` is a sequence of `[ u32 len ][ cert-DER ]`.
 *
 * The signature covers `signedDataBytes`; the content digest is recomputed from
 * the APK (see content-digest.ts) and stored inside the digests sequence.
 */
import { readU32LE } from "./binary.js";

export interface DigestEntry {
	algId: number;
	bytes: Uint8Array;
}

export interface SignatureEntry {
	algId: number;
	bytes: Uint8Array;
}

export interface V2Signer {
	signedData: Uint8Array;
	signatures: SignatureEntry[];
	/** Content digest entries parsed from signedData. */
	digests: DigestEntry[];
	certificates: Uint8Array[]; // X.509 DER
	publicKey: Uint8Array; // SubjectPublicKeyInfo DER
}

export interface V3Signer extends V2Signer {
	minSdkVersion: number;
	maxSdkVersion: number;
}

interface Cursor {
	b: Uint8Array;
	off: number;
}

function lp(cursor: Cursor): Uint8Array {
	// Read a [u32 len][bytes] length-prefixed element, advance the cursor.
	const len = readU32LE(cursor.b, cursor.off);
	cursor.off += 4;
	const bytes = cursor.b.subarray(cursor.off, cursor.off + len);
	cursor.off += len;
	return bytes;
}

/** Iterate a `[u32 len][bytes]` sequence with NO outer length prefix. */
function lpEntries(buf: Uint8Array): Uint8Array[] {
	const items: Uint8Array[] = [];
	let off = 0;
	while (off < buf.length) {
		const elen = readU32LE(buf, off);
		off += 4;
		items.push(buf.subarray(off, off + elen));
		off += elen;
	}
	return items;
}

/** Parse a `signature`/`digest` entry: [u32 alg][u32 len][bytes]. */
function parseAlgEntry(entry: Uint8Array): { algId: number; bytes: Uint8Array } {
	const algId = readU32LE(entry, 0);
	const len = readU32LE(entry, 4);
	return { algId, bytes: entry.subarray(8, 8 + len) };
}

export function parseDigests(entries: Uint8Array[]): DigestEntry[] {
	return entries.map((e) => parseAlgEntry(e));
}

export function parseSignatures(entries: Uint8Array[]): SignatureEntry[] {
	return entries.map((e) => parseAlgEntry(e));
}

/**
 * Parse the v2/v3 signer blocks out of a chunk's data payload.
 * `isV3` selects whether minSdkVersion/maxSdkVersion are read from the signer.
 */
export function parseSigners(chunkData: Uint8Array, isV3: boolean): (V2Signer | V3Signer)[] {
	// chunkData = [ u32 len ][ signersSeq ]  ;  signersSeq = [ u32 len ][ signerBlock ] × N
	const outerLen = readU32LE(chunkData, 0);
	const signersSeq = chunkData.subarray(4, 4 + outerLen);
	const cur: Cursor = { b: signersSeq, off: 0 };
	const signers: (V2Signer | V3Signer)[] = [];
	while (cur.off < signersSeq.length) {
		const slen = readU32LE(cur.b, cur.off);
		cur.off += 4;
		const signerBlock = cur.b.subarray(cur.off, cur.off + slen);
		cur.off += slen;
		signers.push(parseSignerBlock(signerBlock, isV3));
	}
	return signers;
}

function parseSignerBlock(signerBlock: Uint8Array, isV3: boolean): V2Signer | V3Signer {
	const cur: Cursor = { b: signerBlock, off: 0 };
	const signedData = lp(cur);
	let minSdk = 0;
	let maxSdk = 0;
	if (isV3) {
		minSdk = readU32LE(cur.b, cur.off);
		cur.off += 4;
		maxSdk = readU32LE(cur.b, cur.off);
		cur.off += 4;
	}
	const sigsContent = lp(cur);
	const signatures = parseSignatures(lpEntries(sigsContent));
	const publicKey = lp(cur);

	// signedDataBytes = [u32 len][digests][u32 len][certs][u32 len][addlAttrs][(u32 0)[empty]]
	const sd = { b: signedData, off: 0 };
	const digestsContent = lp(sd);
	const digests = parseDigests(lpEntries(digestsContent));
	const certsContent = lp(sd);
	const certificates = lpEntries(certsContent); // cert DERs
	const addlContent = lp(sd); // additional attributes (skip)
	// v2 may have a trailing [u32 0] "empty" element; v3 does not.
	if (!isV3 && sd.off < signedData.length) {
		lp(sd); // discard the empty additional-attributes element
	}

	const base: V2Signer = { signedData, signatures, digests, certificates, publicKey };
	if (isV3) return { ...base, minSdkVersion: minSdk, maxSdkVersion: maxSdk } as V3Signer;
	return base;
}

import { hex } from "./binary.js";
import { sigAlgInfo, verifySig, digestHashForAlgId } from "./alg.js";
import { computeContentDigest } from "./content-digest.js";
import { certInfo } from "./cert-info.js";
import { parseX509Cert } from "./asn1.js";
import { SchemeResult } from "../types.js";

/** Result of verifying a single v2/v3 signer. */
export interface SignerVerification {
	verified: boolean;
	errors: string[];
}

/**
 * Verify a parsed v2/v3 signer: each signature must verify over the signer's
 * `signedData` (using `publicKey`/SPKI), and the APK's recomputed content digest
 * must match the digest stored in the signer's `digests`. A mismatch in either is
 * reported; the content digest is what catches APK-body tampering.
 */
export async function verifySigner(
	apk: Uint8Array,
	signer: V2Signer | V3Signer,
	blockStart: number,
	cdOff: number,
	eocdOff: number,
): Promise<SignerVerification> {
	const errors: string[] = [];
	let sigOk = false;
	let sigTried = false;

	// 1) Signatures over signedData, using the embedded SPKI.
	for (const sig of signer.signatures) {
		const info = sigAlgInfo(sig.algId);
		if (!info) {
			errors.push(`v2/v3: unsupported signature algorithm id ${sig.algId}`);
			continue;
		}
		sigTried = true;
		try {
			// Confirm the cert's SPKI matches the signer's stated public key.
			const ok = await verifySig(info, signer.publicKey, sig.bytes, signer.signedData);
			if (ok) sigOk = true;
			else errors.push(`v2/v3: signature (${info.jca}) did not verify`);
		} catch (e) {
			errors.push(`v2/v3: signature verify failed: ${(e as Error).message}`);
		}
	}
	if (sigTried && !sigOk) errors.push("v2/v3: no signature verified");

	// 2) Content digests: recompute from the APK and compare to the stored values.
	let digestOk = signer.digests.length > 0;
	let digestTried = false;
	for (const d of signer.digests) {
		const hash = digestHashForAlgId(d.algId);
		if (hash === null) continue;
		digestTried = true;
		const recomputed = await computeContentDigest(apk, blockStart, cdOff, eocdOff, hash);
		if (hex(recomputed) !== hex(d.bytes)) {
			digestOk = false;
			errors.push(`v2/v3: content digest mismatch (tampered?) for alg ${d.algId}`);
		}
	}
	if (digestTried && !digestOk) errors.push("v2/v3: content digest mismatch");

	// 3) Certificate must carry the signer's public key.
	if (signer.certificates.length > 0) {
		const cert = signer.certificates[0];
		try {
			const parsed = parseX509Cert(cert);
			if (!equalBytes(parsed.spki, signer.publicKey)) {
				errors.push("v2/v3: signer certificate public key did not match signatures record");
				digestOk = false;
			}
		} catch (e) {
			errors.push(`v2/v3: cert parse failed: ${(e as Error).message}`);
		}
	}

	return { verified: sigOk && digestOk, errors };
}

/**
 * Parse + verify every signer in a v2/v3 chunk. Returns the aggregate scheme
 * result with signer certificate info.
 */
export async function verifyScheme(
	apk: Uint8Array,
	chunkData: Uint8Array,
	blockStart: number,
	cdOff: number,
	eocdOff: number,
	isV3: boolean,
): Promise<SchemeResult> {
	let signers: (V2Signer | V3Signer)[];
	try {
		signers = parseSigners(chunkData, isV3);
	} catch (e) {
		return { present: false, passed: false, signers: [], errors: [`parse failed: ${(e as Error).message}`] };
	}
	if (signers.length === 0) return { present: true, passed: false, signers: [], errors: ["no signers"] };

	const signersOut = [];
	let passed = false;
	const errors: string[] = [];
	for (const s of signers) {
		const { verified, errors: perErrors } = await verifySigner(apk, s, blockStart, cdOff, eocdOff);
		if (perErrors.length) errors.push(...perErrors);
		let cert = null;
		if (s.certificates.length > 0) {
			cert = await certInfo(s.certificates[0]).catch(() => null);
		}
		if (cert) signersOut.push(cert);
		if (verified) passed = true;
	}
	return { present: true, passed, signers: signersOut, errors };
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

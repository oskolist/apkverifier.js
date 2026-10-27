/**
 * Locating & iterating the APK Signature Scheme v2/v3 "APK signing block".
 *
 * The block lives immediately before the ZIP central directory and is framed by:
 *
 *   [ u64 size1 ][ chunks... ][ u64 size2 ][ 16-byte magic "APK Sig Block 42" ]
 *
 * where `size1 == size2` and the whole block starts on a 4 KiB boundary
 * (`blockStart % 4096 == 0`). Each chunk is:
 *
 *   [ u64 size ][ u32 id ][ data ]   (size == 12 + data.length)
 *
 * v2 chunk id  = 0x7109871a (APK_SIGNATURE_SCHEME_V2_BLOCK_ID)
 * v3 chunk id  = 0xf05368c0 (APK_SIGNATURE_SCHEME_V3_BLOCK_ID)
 */
import { readU32LE, readU64LE } from "./binary.js";

export const MAGIC = new TextEncoder().encode("APK Sig Block 42");
export const V2_BLOCK_ID = 0x7109871a;
export const V3_BLOCK_ID = 0xf05368c0;
export const APK_SIGN_BLOCK_SIZE = 16; // bytes

export interface SigningBlockChunk {
	id: number;
	/** The chunk "data" payload (excluding the 12-byte [u64 size][u32 id] header). */
	data: Uint8Array;
}

export interface SigningBlock {
	blockStart: number;
	size1: number;
	size2: number;
	/** Magic byte offset (end of the block, just before the central directory). */
	magicOff: number;
	chunks: SigningBlockChunk[];
}

/**
 * Locate the APK signing block. Returns `undefined` when no v2/v3 signing block
 * is present (e.g. a v1-only APK).
 */
export function findSigningBlock(data: Uint8Array, cdOff: number): SigningBlock | undefined {
	// The 16-byte magic sits immediately before the central directory.
	const magicOff = cdOff - APK_SIGN_BLOCK_SIZE;
	if (magicOff < 8) return undefined;
	if (!equals(data, magicOff, MAGIC)) return undefined;

	const size2 = readU64LE(data, magicOff - 8);
	const blockStart = cdOff - 8 - size2;
	if (blockStart < 0) return undefined;
	if (blockStart + 8 > data.length) return undefined;
	const size1 = readU64LE(data, blockStart);
	if (size1 !== size2) return undefined; // integrity check (apksig: size1 == size2)

	// The block must be 4 KiB page aligned (apksig verifyIntegrity enforces this).
	if (blockStart % 4096 !== 0) return undefined;

	const chunks = iterateChunks(data, blockStart + 8, magicOff - 8);
	return { blockStart, size1, size2, magicOff, chunks };
}

function iterateChunks(data: Uint8Array, start: number, end: number): SigningBlockChunk[] {
	const chunks: SigningBlockChunk[] = [];
	let off = start;
	while (off + 12 <= end) {
		// chunk u64 size EXCLUDES the 8-byte size field itself: = 4 (id) + valueLen.
		const sz = Number(readU64LE(data, off));
		const dataEnd = off + 8 + sz; // span = 8 (size field) + sz
		if (sz < 4 || dataEnd > end) {
			// malformed / padding boundary; stop to avoid an infinite loop
			break;
		}
		const id = readU32LE(data, off + 8);
		const valueStart = off + 12;
		chunks.push({ id, data: data.subarray(valueStart, dataEnd) });
		off = dataEnd;
	}
	return chunks;
}

export function findChunk(chunks: SigningBlockChunk[], id: number): SigningBlockChunk | undefined {
	return chunks.find((c) => c.id === id);
}

function equals(a: Uint8Array, off: number, b: Uint8Array): boolean {
	if (off + b.length > a.length) return false;
	for (let i = 0; i < b.length; i++) if (a[off + i] !== b[i]) return false;
	return true;
}

/**
 * The v2/v3 chunk payload is a length-prefixed SEQUENCE of length-prefixed
 * signer blocks:
 *
 *   chunkData = [ u32 len ][ signersSeq ]
 *   signersSeq = [ u32 len ][ signerBlock ]   (repeated per signer)
 *
 * Each `signerBlock` is parsed by the v2/v3 verifiers.
 */
export function parseSignerSequence(chunkData: Uint8Array): Uint8Array[] {
	const signers: Uint8Array[] = [];
	let p = 0;
	if (readU32LE(chunkData, 0) !== chunkData.length - 4) {
		// tolerate but prefer the explicit length: read the outer length prefix
	}
	// Outer element: [ u32 len ][ payload ]
	const outerLen = readU32LE(chunkData, p);
	p += 4;
	const outerEnd = p + outerLen;
	// Inside: a SEQUENCE of length-prefixed signer blocks
	while (p < outerEnd) {
		const slen = readU32LE(chunkData, p);
		p += 4;
		signers.push(chunkData.subarray(p, p + slen));
		p += slen;
	}
	return signers;
}

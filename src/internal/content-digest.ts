/**
 * APK Signature Scheme v2/v3 *content digest* ("CHUNKED_SHA256" /
 * "CHUNKED_SHA512").
 *
 * The whole APK (minus the signing block) is split into three ordered sources:
 *
 *   1. bytes before the signing block        = apk[0 .. blockStart]
 *   2. the central directory                 = apk[cdOff .. eocdOff]
 *   3. the EOCD record, with its central-dir-offset field (at eocdOff+16)
 *      patched to `blockStart`
 *
 * Each source is split into 1 MiB chunks; each chunk becomes
 * `SHA-{h}( 0xa5 | u32-le(chunkLen) | chunk )`, then the final digest is
 * `SHA-{h}( 0x5a | u32-le(chunkCount) | concat(chunkDigests) )`.
 *
 * This mirrors `ApkSigningBlockUtils.computeOneMbChunkContentDigests` /
 * `ChunkDigester` and was validated byte-for-byte against the v2only.apk fixture.
 */
import { readU32LE, sha256, sha512, concat } from "./binary.js";

const CHUNK_SIZE = 1024 * 1024; // 1 MiB (apksig "1 MB chunks")
const PER_CHUNK_PREFIX = 0xa5;
const FINAL_PREFIX = 0x5a;

export type ChunkHashFn = (data: Uint8Array) => Promise<Uint8Array>;

export function chunkHasher(hash: string): ChunkHashFn {
	return hash === "SHA-512" ? sha512 : sha256;
}

/** Read the EOCD comment length; the EOCD record is 22 bytes + comment. */
export function eocdTotalLen(data: Uint8Array, eocdOff: number): number {
	// EOCD comment length is a u16 at eocdOff+20 (reading 4 bytes would overrun).
	const commentLen = data[eocdOff + 20] | (data[eocdOff + 21] << 8);
	return 22 + commentLen;
}

export async function computeContentDigest(
	apk: Uint8Array,
	blockStart: number,
	cdOff: number,
	eocdOff: number,
	hash: string,
): Promise<Uint8Array> {
	const h = chunkHasher(hash);

	const before = apk.subarray(0, blockStart);
	const centralDir = apk.subarray(cdOff, eocdOff);
	// EOCD record (with comment) and patch its central-directory-offset field.
	const eocdLen = eocdTotalLen(apk, eocdOff);
	const eocd = apk.subarray(eocdOff, eocdOff + eocdLen);
	const sources: Uint8Array[] = [];
	// shallow-copy the EOCD and patch the CD offset (u32 @ offset 16) to blockStart
	{
		const copy = eocd.slice();
		writeU32LE(copy, 16, blockStart);
		sources.push(before, centralDir, copy);
	}

	const chunkDigests: Uint8Array[] = [];
	for (const s of sources) {
		for (let i = 0; i < s.length; i += CHUNK_SIZE) {
			const chunk = s.subarray(i, i + CHUNK_SIZE);
			const header = new Uint8Array(5);
			header[0] = PER_CHUNK_PREFIX;
			writeU32LE(header, 1, chunk.length);
			chunkDigests.push(await h(concat([header, chunk])));
		}
	}

	const body = concatAll(chunkDigests);
	const out = new Uint8Array(5 + body.length);
	out[0] = FINAL_PREFIX;
	writeU32LE(out, 1, chunkDigests.length);
	out.set(body, 5);
	return h(out);
}

function writeU32LE(b: Uint8Array, off: number, v: number): void {
	b[off] = v & 0xff;
	b[off + 1] = (v >>> 8) & 0xff;
	b[off + 2] = (v >>> 16) & 0xff;
	b[off + 3] = (v >>> 24) & 0xff;
}

function concatAll(parts: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const p of parts) total += p.length;
	const out = new Uint8Array(total);
	let pos = 0;
	for (const p of parts) {
		out.set(p, pos);
		pos += p.length;
	}
	return out;
}

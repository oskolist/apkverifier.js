/**
 * Low-level binary primitives: little-endian integer readers, hex encoding, byte
 * concatenation, and WebCrypto-backed hashing / signature verification.
 *
 * No Node.js specific APIs are used here. Everything runs on the DOM `crypto`
 * (WebCrypto) global and the platform `DecompressionStream`, so the module works
 * in both Node.js (>= 22) and modern browsers.
 */

const HEX = "0123456789abcdef";

/** Read a little-endian uint32 from `buf` at `off`. */
export function readU32LE(buf: Uint8Array, off: number): number {
	const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	return dv.getUint32(off, true);
}

/** Read a little-endian uint64 from `buf` at `off` as a JS number (sizes here
 *  are never larger than 2^53 so `Number` is safe). */
export function readU64LE(buf: Uint8Array, off: number): number {
	const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	return Number(dv.getBigUint64(off, true));
}

/** Read a big-endian uint32 from `buf` at `off` (used for ASN.1 / X.509). */
export function readU32BE(buf: Uint8Array, off: number): number {
	const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	return dv.getUint32(off, false);
}

/** Return the hex representation of `buf`. */
export function hex(buf: Uint8Array): string {
	let s = "";
	for (let i = 0; i < buf.length; i++) {
		s += HEX[(buf[i] & 0xf0) >> 4] + HEX[buf[i] & 0x0f];
	}
	return s;
}

/** Concatenate any number of byte-ish values into a single Uint8Array. */
export function concat(parts: ReadonlyArray<Uint8Array | ArrayBuffer>): Uint8Array {
	let total = 0;
	for (const p of parts) total += p.byteLength;
	const out = new Uint8Array(total);
	let pos = 0;
	for (const p of parts) {
		const src = p instanceof Uint8Array ? p : new Uint8Array(p as ArrayBuffer);
		out.set(src, pos);
		pos += src.length;
	}
	return out;
}

/** SHA-256 digest via WebCrypto. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
	const buf = await crypto.subtle.digest("SHA-256", data as BufferSource);
	return new Uint8Array(buf as ArrayBuffer);
}

/** SHA-512 digest via WebCrypto. */
export async function sha512(data: Uint8Array): Promise<Uint8Array> {
	const buf = await crypto.subtle.digest("SHA-512", data as BufferSource);
	return new Uint8Array(buf as ArrayBuffer);
}

/** SHA-1 digest via WebCrypto (used only for cert fingerprints, not signing). */
export async function sha1(data: Uint8Array): Promise<Uint8Array> {
	const buf = await crypto.subtle.digest("SHA-1", data as BufferSource);
	return new Uint8Array(buf as ArrayBuffer);
}

/**
 * Raw-deflate decompress (`windowBits = -15`) using the platform
 * `DecompressionStream('deflate-raw')` (Node >= 16, Edge, Chrome, Firefox).
 */
export async function inflateRaw(data: Uint8Array): Promise<Uint8Array> {
	const stream = new DecompressionStream("deflate-raw");
	const writer = stream.writable.getWriter();
	const reader = stream.readable.getReader();

	await writer.write(data as BufferSource);
	await writer.close();

	const chunks: Uint8Array[] = [];
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		chunks.push(value!);
	}
	return concat(chunks);
}

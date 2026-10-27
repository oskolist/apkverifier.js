/**
 * Minimal ZIP / EOCD / Central-Directory reader for APKs.
 *
 * APKs are ZIP archives; the central directory (and its offset) is what the
 * APK Signature Scheme v2/v3 content-digest computation refers to, so we parse
 * just enough: EOCD, central-directory records, and local-file data (with raw
 * deflate decompression for v1 manifest digests). No `zlib`/`buffer` dependency.
 */
import { inflateRaw } from "./binary.js";
import { readU32LE, readU64LE } from "./binary.js";

export interface ZipEntry {
	/** Entry name (UTF-8). */
	name: string;
	/** Compression method (0 = stored, 8 = deflate). */
	method: number;
	compressedSize: number;
	uncompressedSize: number;
	crc32: number;
	/** Byte offset of this entry's local file header in `data`. */
	offset: number;
}

export interface ZipSections {
	/** File offset of the End-Of-Central-Directory record. */
	eocdOff: number;
	/** File offset where the central directory begins. */
	cdOff: number;
	/** Size (bytes) of the central directory. */
	cdSize: number;
	/** All central-directory entries, in order. */
	entries: ZipEntry[];
	/** Byte offset where the last local entry's data ends (= central dir start,
	 *  before any APK signing block is inserted). */
	dataEnd: number;
}

const LFH_SIG = 0x04034b50;
const CDH_SIG = 0x02014b50;
const EOCD_SIG = 0x06054b50;

/** Find the EOCD record by scanning backwards for `PK\x05\x06`. */
export function findEocd(data: Uint8Array): number {
	for (let i = data.length - 22; i >= 0; i--) {
		if (data[i] !== 0x50 || data[i + 1] !== 0x4b || data[i + 2] !== 0x05 || data[i + 3] !== 0x06) continue;
		// comment length is a u16 at eocd+20
		const commentLen = data[i + 20] | (data[i + 21] << 8);
		if (i + 22 + commentLen === data.length) return i;
	}
	// Fallback: last signature match (some writers pad differently).
	for (let i = data.length - 22; i >= 0; i--) {
		if (data[i] !== 0x50 || data[i + 1] !== 0x4b || data[i + 2] !== 0x05 || data[i + 3] !== 0x06) continue;
		return i;
	}
	throw new Error("ZIP: EOCD record not found");
}

export function getZipSections(data: Uint8Array): ZipSections {
	const eocdOff = findEocd(data);
	const cdOff = readU32LE(data, eocdOff + 16);
	const cdSize = readU32LE(data, eocdOff + 12);
	// totalEntries is a u16 at eocdOff+10; read as u32 and mask to 16 bits.
	const totalEntries = readU32LE(data, eocdOff + 10) & 0xffff;

	const entries: ZipEntry[] = [];
	let off = cdOff;
	let maxDataEnd = cdOff;
	for (let i = 0; i < totalEntries; i++) {
		if (readU32LE(data, off) !== CDH_SIG) throw new Error(`ZIP: bad central directory header @ ${off}`);
		const method = readU32LE(data, off + 10) & 0xffff;
		// crc32 at off+16 (4), compressed size at off+20 (4), uncompressed at off+24 (4)
		const compressedSize = readU32LE(data, off + 20);
		const uncompressedSize = readU32LE(data, off + 24);
		const nameLen = readU32LE(data, off + 28) & 0xffff;
		const extraLen = readU32LE(data, off + 30) & 0xffff;
		const commentLen = readU32LE(data, off + 32) & 0xffff;
		const lfhOff = readU32LE(data, off + 42);
		const name = decodeUtf8(data.subarray(off + 46, off + 46 + nameLen));
		entries.push({ name, method, compressedSize, uncompressedSize, crc32: 0, offset: lfhOff });
		// advance past this central directory entry
		off += 46 + nameLen + extraLen + commentLen;
		// track the end of the local data for this entry (used as a rough bound)
		const dataEnd = lfhOff + localHeaderSize(data, lfhOff) + compressedSize;
		if (dataEnd > maxDataEnd) maxDataEnd = dataEnd;
	}
	return { eocdOff, cdOff, cdSize, entries, dataEnd: maxDataEnd };
}

/** Size of a local file header (including its name + extra) at `lfhOff`. */
function localHeaderSize(data: Uint8Array, lfhOff: number): number {
	if (readU32LE(data, lfhOff) !== LFH_SIG) throw new Error(`ZIP: bad local header @ ${lfhOff}`);
	const nameLen = readU32LE(data, lfhOff + 26) & 0xffff;
	const extraLen = readU32LE(data, lfhOff + 28) & 0xffff;
	return 30 + nameLen + extraLen;
}

/** Return the (possibly decompressed) bytes of a stored/deflated entry. */
export async function readEntry(data: Uint8Array, entry: ZipEntry): Promise<Uint8Array> {
	const hdrSize = localHeaderSize(data, entry.offset);
	const dataOff = entry.offset + hdrSize;
	const compressed = data.subarray(dataOff, dataOff + entry.compressedSize);
	if (entry.method === 0) return compressed; // stored
	if (entry.method === 8) return inflateRaw(compressed); // raw deflate
	throw new Error(`ZIP: unsupported method ${entry.method} for ${entry.name}`);
}

function decodeUtf8(bytes: Uint8Array): string {
	return new TextDecoder("utf-8").decode(bytes);
}

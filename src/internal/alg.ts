/**
 * APK Signature Scheme algorithm-id -> {hash, WebCrypto algorithm}.
 *
 * v2/v3 ids (apksig `SignatureAlgorithm` integer ids):
 *   257 = RSA-PSS  / SHA-256, 258 = RSA-PSS  / SHA-512
 *   259 = RSA-PKCS1/ SHA-256, 260 = RSA-PKCS1/ SHA-512
 *   513 = ECDSA    / SHA-256, 514 = ECDSA    / SHA-512
 *
 * The v2/v3 content-digest algorithm is the *chunked* digest whose hash matches
 * the signature algorithm's digest (CHUNKED_SHA256 / CHUNKED_SHA512).
 */
import { OID, readTLV, children, decodeOid } from "./asn1.js";

/** Field size in bytes for the standard WebCrypto ECDSA named curves. */
const NAMED_CURVE_BYTES: Record<string, number> = {
	"P-256": 32,
	"P-384": 48,
	"P-521": 66,
};

/** Convert a DER-encoded ECDSA signature (SEQUENCE { r INTEGER, s INTEGER }) to
 *  the raw r‖s form (each integer left-padded to `fieldBytes`). Returns null if
 *  the input is not a parseable DER ECDSA signature. */
export function derToRawEcdsa(sig: Uint8Array, fieldBytes: number): Uint8Array | null {
	const b = sig;
	if (b.length < 8 || b[0] !== 0x30) return null;
	let p = 2;
	let len = b[1];
	if (len & 0x80) {
		const n = len & 0x7f;
		if (n < 1 || n > 2 || p + n > b.length) return null;
		len = 0;
		for (let i = 0; i < n; i++) len = (len << 8) | b[p++];
	}
	const end = p + len;
	if (end > b.length) return null;
	const r = readDerInt(b, p, fieldBytes, end);
	if (r === null) return null;
	p = r.next;
	const s = readDerInt(b, p, fieldBytes, end);
	if (s === null) return null;
	if (s.next !== end) return null;
	const out = new Uint8Array(fieldBytes * 2);
	out.set(r.bytes, 0);
	out.set(s.bytes, fieldBytes);
	return out;
}

interface DerIntResult { bytes: Uint8Array; next: number; }
function readDerInt(b: Uint8Array, p: number, fieldBytes: number, end: number): DerIntResult | null {
	if (p >= end || b[p] !== 0x02) return null;
	p++;
	let ilen = b[p++];
	if (ilen & 0x80) {
		const n = ilen & 0x7f;
		if (n < 1 || p + n > end) return null;
		ilen = 0;
		for (let i = 0; i < n; i++) ilen = (ilen << 8) | b[p++];
	}
	if (p + ilen > end || ilen > fieldBytes + 1) return null;
	// strip a single leading 0x00 (minimal DER positive encoding); left-pad to fieldBytes
	const src = b.subarray(p, p + ilen);
	const out = new Uint8Array(fieldBytes);
	let start = 0;
	if (src.length === fieldBytes + 1 && src[0] === 0x00) start = 1; // leading zero keeps it positive
	out.set(src.subarray(start), fieldBytes - (src.length - start));
	return { bytes: out, next: p + ilen };
}

export type HashName = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

export interface SigAlgorithmInfo {
	/** Digest algorithm used for both the content digest and the signature hash. */
	readonly hash: HashName;
	/** JCA / human-readable name (diagnostics). */
	readonly jca: string;
	/** Whether this is an EC signature algorithm (curve resolved from the SPKI). */
	readonly isEc: boolean;
	/** Algorithm for `crypto.subtle.verify(alg, key, sig, data)` (DOM `AlgorithmIdentifier`). */
	readonly verifyAlg: AlgorithmIdentifier;
	/** Algorithm for `crypto.subtle.importKey("spki", spki, alg, ...)`. */
	readonly importAlg: AlgorithmIdentifier;
}

export const RSA_PKCS1_SHA256 = 259;
export const RSA_PKCS1_SHA512 = 260;
export const RSA_PSS_SHA256 = 257;
export const RSA_PSS_SHA512 = 258;
export const ECDSA_SHA256 = 513;
export const ECDSA_SHA512 = 514;

const TABLE: Record<number, SigAlgorithmInfo> = {
	[RSA_PSS_SHA256]: {
		hash: "SHA-256",
		jca: "SHA256withRSA/PSS",
		isEc: false,
		verifyAlg: { name: "RSA-PSS", hash: "SHA-256", saltLength: 32 } as AlgorithmIdentifier,
		importAlg: { name: "RSA-PSS", hash: "SHA-256" } as AlgorithmIdentifier,
	},
	[RSA_PSS_SHA512]: {
		hash: "SHA-512",
		jca: "SHA512withRSA/PSS",
		isEc: false,
		verifyAlg: { name: "RSA-PSS", hash: "SHA-512", saltLength: 64 } as AlgorithmIdentifier,
		importAlg: { name: "RSA-PSS", hash: "SHA-512" } as AlgorithmIdentifier,
	},
	[RSA_PKCS1_SHA256]: {
		hash: "SHA-256",
		jca: "SHA256withRSA",
		isEc: false,
		verifyAlg: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as AlgorithmIdentifier,
		importAlg: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as AlgorithmIdentifier,
	},
	[RSA_PKCS1_SHA512]: {
		hash: "SHA-512",
		jca: "SHA512withRSA",
		isEc: false,
		verifyAlg: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" } as AlgorithmIdentifier,
		importAlg: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" } as AlgorithmIdentifier,
	},
	[ECDSA_SHA256]: {
		hash: "SHA-256",
		jca: "SHA256withECDSA",
		isEc: true,
		verifyAlg: { name: "ECDSA", hash: "SHA-256" } as AlgorithmIdentifier,
		importAlg: { name: "ECDSA", namedCurve: "P-256" } as AlgorithmIdentifier,
	},
	[ECDSA_SHA512]: {
		hash: "SHA-512",
		jca: "SHA512withECDSA",
		isEc: true,
		verifyAlg: { name: "ECDSA", hash: "SHA-512" } as AlgorithmIdentifier,
		importAlg: { name: "ECDSA", namedCurve: "P-521" } as AlgorithmIdentifier,
	},
};

/** Resolve a v2/v3 integer signature-algorithm ID. */
export function sigAlgInfo(algId: number): SigAlgorithmInfo | null {
	return TABLE[algId] ?? null;
}

const OID_TO_HASH: Record<string, HashName> = {
	[OID.SHA1]: "SHA-1",
	[OID.SHA256]: "SHA-256",
	[OID.SHA384]: "SHA-384",
	[OID.SHA512]: "SHA-512",
};

export function oidToHash(oid: string): HashName | null {
	return OID_TO_HASH[oid] ?? null;
}

/** Map a PKCS#7 signature-algorithm *OID* (v1/JAR) into a SigAlgorithmInfo. */
export function oidToSigInfo(sigOid: string, digestOid: string): SigAlgorithmInfo | null {
	const hash = OID_TO_HASH[digestOid];
	if (!hash) return null;
	const digestPrefix = hash === "SHA-1" ? "SHA1" : hash.replace("SHA-", "SHA");
	// "Bare" key-algorithm OIDs (apksigner emits rsaEncryption / id-ecPublicKey and
	// carries the digest in a *separate* digestAlgorithm field) combine with the
	// digest OID to form the JCA signature name, exactly like apksig's
	// `AlgorithmIdentifier.getJcaSignatureAlgorithm`.
	let keyType: "RSA" | "EC" | "DSA" | null = null;
	if (sigOid === OID.RSA_ENCRYPTION) keyType = "RSA";
	else if (sigOid === OID.EC_PUBLIC_KEY) keyType = "EC";
	else if (sigOid === OID.DSA) keyType = "DSA";
	else {
		// Specific signature OIDs (digest implied by the OID); reject if the implied
		// digest disagrees with the declared digestAlgorithm.
		const specific = OID_TO_SIG[sigOid];
		if (!specific) return null;
		if (specific.digestPrefix !== digestPrefix) return null;
		keyType = specific.keyType;
	}
	if (keyType === "RSA") {
		return {
			hash,
			jca: digestPrefix + "withRSA",
			isEc: false,
			verifyAlg: { name: "RSASSA-PKCS1-v1_5", hash } as AlgorithmIdentifier,
			importAlg: { name: "RSASSA-PKCS1-v1_5", hash } as AlgorithmIdentifier,
		};
	}
	if (keyType === "EC") {
		return {
			hash,
			jca: digestPrefix + "withECDSA",
			isEc: true,
			verifyAlg: { name: "ECDSA", hash } as AlgorithmIdentifier,
			importAlg: { name: "ECDSA", namedCurve: "P-256" } as AlgorithmIdentifier,
		};
	}
	return null; // DSA not supported by WebCrypto ECDSA; apksigner never emits it.
}

/** Specific signature-algorithm OIDs carry their own digest. */
const OID_TO_SIG: Record<string, { digestPrefix: string; keyType: "RSA" | "EC" | "DSA" }> = {
	[OID.SHA1_WITH_RSA]: { digestPrefix: "SHA1", keyType: "RSA" },
	[OID.SHA256_WITH_RSA]: { digestPrefix: "SHA256", keyType: "RSA" },
	[OID.SHA384_WITH_RSA]: { digestPrefix: "SHA384", keyType: "RSA" },
	[OID.SHA512_WITH_RSA]: { digestPrefix: "SHA512", keyType: "RSA" },
	[OID.SHA1_WITH_ECDSA]: { digestPrefix: "SHA1", keyType: "EC" },
	[OID.SHA256_WITH_ECDSA]: { digestPrefix: "SHA256", keyType: "EC" },
	[OID.SHA384_WITH_ECDSA]: { digestPrefix: "SHA384", keyType: "EC" },
	[OID.SHA512_WITH_ECDSA]: { digestPrefix: "SHA512", keyType: "EC" },
};

const EC_CURVE_OID_TO_NAMED: Record<string, string> = {
	"1.2.840.10045.3.1.7": "P-256", // secp256r1 / prime256v1
	"1.2.840.10045.3.1.6": "P-384", // secp384r1
};

/** Extract the named-curve OID from an EC SubjectPublicKeyInfo (id-ecPublicKey params). */
export function ecCurveOid(spki: Uint8Array): string {
	try {
		const root = readTLV(spki, 0); // SubjectPublicKeyInfo SEQUENCE
		const algId = readTLV(spki, root.off); // AlgorithmIdentifier SEQUENCE
		const items = children(spki, algId.off, algId.len);
		// items[0] = algorithm OID (id-ecPublicKey), items[1] = named-curve OID
		if (items.length >= 2 && items[1].tag === 0x06) return decodeOid(spki, items[1].off, items[1].len);
	} catch {
		/* fall through */
	}
	return "";
}

/** Pick the namedCurve string for an EC SPKI, fixing up the importAlg. */
export function ecNamedCurve(spki: Uint8Array): string {
	const oid = ecCurveOid(spki);
	const name = EC_CURVE_OID_TO_NAMED[oid];
	if (!name) throw new Error(`unsupported EC curve OID ${oid}`);
	return name;
}

/** Import an X.509/SPKI SubjectPublicKeyInfo as a WebCrypto public key. */
export async function importSpki(spki: Uint8Array, info: SigAlgorithmInfo): Promise<CryptoKey> {
	const imp: AlgorithmIdentifier = { ...(info.importAlg as object) } as AlgorithmIdentifier;
	if (info.isEc) {
		const ec = imp as unknown as Record<string, unknown>;
		ec.namedCurve = ecNamedCurve(spki);
	}
	return crypto.subtle.importKey("spki", spki as BufferSource, imp, false, ["verify"]) as Promise<CryptoKey>;
}

/** Verify `sig` over `data` using the public key in `spki`. */
export async function verifySig(info: SigAlgorithmInfo, spki: Uint8Array, sig: Uint8Array, data: Uint8Array): Promise<boolean> {
	const key = await importSpki(spki, info);
	// apksig stores ECDSA signatures as DER (SEQUENCE { r, s }). Node's
	// `crypto.subtle` ECDSA verify expects raw r‖s (IEEE P1363), while browsers
	// follow the W3C spec and expect DER. Try the signature as-is first, then
	// fall back to raw r‖s.
	if (info.isEc) {
		if (await crypto.subtle.verify(info.verifyAlg, key, sig as BufferSource, data as BufferSource)) return true;
		const namedCurve = (key.algorithm as unknown as { namedCurve?: string }).namedCurve;
		const fieldBytes = namedCurve ? NAMED_CURVE_BYTES[namedCurve] : 0;
		if (fieldBytes) {
			const raw = derToRawEcdsa(sig, fieldBytes);
			if (raw && (await crypto.subtle.verify(info.verifyAlg, key, raw as BufferSource, data as BufferSource))) return true;
		}
		return false;
	}
	return (await crypto.subtle.verify(info.verifyAlg, key, sig as BufferSource, data as BufferSource)) === true;
}

/** Digest-hash for a v2/v3 digest-entry algorithm id (259 -> SHA-256, 260 -> SHA-512, ...). */
export function digestHashForAlgId(algId: number): HashName | null {
	const info = sigAlgInfo(algId);
	return info ? info.hash : null;
}

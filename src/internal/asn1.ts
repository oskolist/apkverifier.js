/**
 * Minimal ASN.1 DER reader used by the v1 (JAR/PKCS#7) path and to extract
 * X.509 SubjectPublicKeyInfo / certificate fingerprints for v1/v2/v3.
 *
 * It deliberately supports only the DER constructs produced by apksigner:
 * SEQUENCE, SET, OID, INTEGER, OCTET STRING, BIT STRING, NULL, context tags
 * ([n] implicit/explicit) and the lengths/oids used by PKCS#7 / X.509 / SPKI.
 */

/* ------------------------------------------------------------------ TLV */

export interface TLV {
	/** Raw tag byte (low 5 bits = tag number for primitive/universal). */
	tag: number;
	/** Number of bytes used by the length octets (1+1 or 1+3 etc.). */
	hlen: number;
	/** Content length (value bytes). */
	len: number;
	/** Offset of the first content byte. */
	off: number;
	/** Offset of the first byte after this TLV. */
	next: number;
}

/** Parse a single TLV at `off`. */
export function readTLV(b: Uint8Array, off: number): TLV {
	const tag = b[off];
	let p = off + 1;
	let len = b[p++];
	if (len & 0x80) {
		const n = len & 0x7f;
		len = 0;
		for (let i = 0; i < n; i++) len = (len << 8) | b[p++];
	}
	const contentOff = p;
	return { tag, hlen: p - off, len, off: contentOff, next: contentOff + len };
}

/** Parse the `len` content bytes starting at `contentOff` into child TLVs. */
export function children(b: Uint8Array, contentOff: number, len: number): TLV[] {
	const end = contentOff + len;
	const out: TLV[] = [];
	let p = contentOff;
	while (p < end) {
		const t = readTLV(b, p);
		out.push(t);
		p = t.next;
	}
	return out;
}

/** Decode an OBJECT IDENTIFIER into its dotted-string form. */
export function decodeOid(b: Uint8Array, contentOff: number, len: number): string {
	const end = contentOff + len;
	const first = b[contentOff];
	const arcs: number[] = [Math.floor(first / 40), first % 40];
	let i = contentOff + 1;
	let val = 0;
	while (i < end) {
		const c = b[i++];
		val = (val << 7) | (c & 0x7f);
		if (!(c & 0x80)) {
			arcs.push(val);
			val = 0;
		}
	}
	return arcs.join(".");
}

/** Decode a base-128 big-endian INTEGER value (positive). */
export function decodeInteger(b: Uint8Array, contentOff: number, len: number): bigint {
	let v = 0n;
	for (let i = 0; i < len; i++) v = (v << 8n) | BigInt(b[contentOff + i]);
	return v;
}

/* -------------------------------------------------------------- OIDs / JCA */

export const OID = {
	// Digest algorithms
	SHA1: "1.3.14.3.2.26",
	SHA256: "2.16.840.1.101.3.4.2.1",
	SHA384: "2.16.840.1.101.3.4.2.2",
	SHA512: "2.16.840.1.101.3.4.2.3",
	// Signature algorithms
	SHA1_WITH_RSA: "1.2.840.113549.1.1.5",
	SHA256_WITH_RSA: "1.2.840.113549.1.1.11",
	SHA384_WITH_RSA: "1.2.840.113549.1.1.12",
	SHA512_WITH_RSA: "1.2.840.113549.1.1.13",
	SHA1_WITH_ECDSA: "1.2.840.10045.4.1",
	SHA256_WITH_ECDSA: "1.2.840.10045.4.3.2",
	SHA384_WITH_ECDSA: "1.2.840.10045.4.3.3",
	SHA512_WITH_ECDSA: "1.2.840.10045.4.3.4",
	RSA_ENCRYPTION: "1.2.840.113549.1.1.1",
	EC_PUBLIC_KEY: "1.2.840.10045.2.1",
	DSA: "1.2.840.10040.4.1",
	// PKCS#7
	SIGNED_DATA: "1.2.840.113549.1.7.2",
	DATA: "1.2.840.113549.1.7.1",
	CONTENT_TYPE: "1.2.840.113549.1.9.3",
	MESSAGE_DIGEST: "1.2.840.113549.1.9.4",
	// EC curves
	SECP256R1: "1.2.840.10045.3.1.7",
	SECP384R1: "1.2.840.10045.3.1.6",
	SECP521R1: "1.3.132.0.35",
} as const;

export const OID_TO_HASH: Record<string, HashName> = {
	[OID.SHA1]: "SHA-1",
	[OID.SHA256]: "SHA-256",
	[OID.SHA384]: "SHA-384",
	[OID.SHA512]: "SHA-512",
};

const OID_TO_EC_CURVE: Record<string, string> = {
	[OID.SECP256R1]: "P-256",
	[OID.SECP384R1]: "P-384",
	[OID.SECP521R1]: "P-521",
};

export const HASH_SHA1 = "SHA-1";
export const HASH_SHA256 = "SHA-256";
export const HASH_SHA384 = "SHA-384";
export const HASH_SHA512 = "SHA-512";

export type HashName = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

export function oidToHash(oid: string): HashName | null {
	return OID_TO_HASH[oid] ?? null;
}

/* ------------------------------------------------------------- X.509 certs */

export interface X509Cert {
	serial: bigint;
	/** DER encoding of the Issuer Name (for SID matching / DN display). */
	issuer: Uint8Array;
	/** DER encoding of the Subject Name. */
	subject: Uint8Array;
	/** The full SubjectPublicKeyInfo DER (tag+len+value) — importable as 'spki'. */
	spki: Uint8Array;
	/** SHA-256 of the whole certificate DER. */
	sha256: string;
	/** Human-friendly subject CN (best-effort). */
	subjectCN: string | null;
}

/** Parse the TBSCertificate to locate the SubjectPublicKeyInfo and metadata. */
export function parseX509Cert(cert: Uint8Array): X509Cert {
	// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
	const root = readTLV(cert, 0);
	if (root.tag !== 0x30) throw new Error("X.509: expected outer SEQUENCE");
	const certChildren = children(cert, root.off, root.len);
	const tbs = certChildren[0]; // TBSCertificate SEQUENCE
	const f = children(cert, tbs.off, tbs.len);

	// version [0] EXPLICIT is optional; serialNumber, signature alg, issuer, validity, subject, SPKI...
	let i = 0;
	if (f[0].tag === 0xa0) i++; // skip version
	const serial = decodeInteger(cert, f[i].off, f[i].len); i++; // serialNumber
	// f[i]   = signature AlgorithmIdentifier (skip)
	// f[i+1] = issuer Name
	// f[i+2] = validity
	// f[i+3] = subject Name
	// f[i+4] = subjectPublicKeyInfo
	const issuer = f[i + 1];
	const subject = f[i + 3];
	const spki = f[i + 4];
	return {
		serial,
		issuer: sl(cert, issuer.off, issuer.len),
		subject: sl(cert, subject.off, subject.len),
		// SubjectPublicKeyInfo is the full TLV (tag + len octets + value), matching
		// the signer's stated public key (which is the complete SPKI DER).
		spki: sl(cert, spki.off - spki.hlen, spki.hlen + spki.len),
		sha256: "",
		subjectCN: extractCN(cert, subject.off, subject.len),
	};
}

function sl(b: Uint8Array, off: number, len: number): Uint8Array {
	return b.slice(off, off + len);
}

/** Best-effort: find a commonName (OID 2.5.4.3) in a Name SEQUENCE. */
export function extractCN(b: Uint8Array, contentOff: number, len: number): string | null {
	// Name ::= SEQUENCE OF RelativeDistinguishedName; RDN ::= SET OF AttributeTypeAndValue
	try {
		const end = contentOff + len;
		let p = contentOff;
		while (p < end) {
			const rdn = readTLV(b, p); // SET OF (0x31)
			if (rdn.tag !== 0x31) { p = rdn.next; continue; }
			const atvList = children(b, rdn.off, rdn.len);
			for (const atv of atvList) {
				if (atv.tag !== 0x30) continue; // SEQUENCE
				const pair = children(b, atv.off, atv.len);
				if (pair.length < 2) continue;
				if (pair[0].tag !== 0x06) continue;
				const oid = decodeOid(b, pair[0].off, pair[0].len);
				if (oid === "2.5.4.3") {
					// value is a DirectoryString (usually UTF8String 0x0c or PrintableString 0x13)
					const v = pair[1];
					const text = decodeString(b, v.off, v.len);
					if (text) return text;
				}
			}
			p = rdn.next;
		}
	} catch {
		/* ignore */
	}
	return null;
}

function decodeString(b: Uint8Array, off: number, len: number): string | null {
	// Try UTF-8; the common case for CN in modern certs.
	try {
		const bytes = b.slice(off, off + len);
		return new TextDecoder().decode(bytes);
	} catch {
		return null;
	}
}

/* --------------------------------------------------------- PKCS#7 SignedData */

export interface Pkcs7SignerInfo {
	/** Signature algorithm OID (e.g. sha256WithRSA). */
	sigAlgOid: string;
	/** Digest algorithm OID (e.g. SHA-256). */
	digestAlgOid: string;
	/** Raw DER bytes of the [0] signedAttrs (a0 <len> <set-or-attrs>). */
	signedAttrsDER: Uint8Array;
	/** Signature value (octet string content). */
	signature: Uint8Array;
	/** Sid issuer DN DER (if issuerAndSerial) + serial. */
	sidIssuer: Uint8Array | null;
	sidSerial: bigint | null;
	/** Message-digest attribute (SHA-x of the signed content / .SF), if present. */
	messageDigest: Uint8Array | null;
}

export interface Pkcs7SignedData {
	encapContentType: string;
	certs: Uint8Array[]; // X.509 DER
	signerInfos: Pkcs7SignerInfo[];
}

/**
 * Parse a PKCS#7 SignedData (the bytes inside META-INF/*.RSA etc.).
 * `der` is the OUTER ContentInfo DER (`30 ... 06 ...<signedData> a0 ...<SignedData>`).
 */
export function parsePkcs7(der: Uint8Array): Pkcs7SignedData {
	const contentInfo = readTLV(der, 0); // SEQUENCE
	if (contentInfo.tag !== 0x30) throw new Error("PKCS#7: expected ContentInfo SEQUENCE");
	const ci = children(der, contentInfo.off, contentInfo.len);
	const contentType = ci[0].tag === 0x06 ? decodeOid(der, ci[0].off, ci[0].len) : "";
	if (contentType !== OID.SIGNED_DATA) throw new Error(`PKCS#7: unexpected content type ${contentType}`);

	// content [0] EXPLICIT -> contains the SignedData SEQUENCE
	const contentField = ci[1];
	if (contentField.tag !== 0xa0) throw new Error("PKCS#7: missing [0] content");
	const contentInner = children(der, contentField.off, contentField.len);
	const signedData = contentInner[0];
	if (signedData.tag !== 0x30) throw new Error("PKCS#7: expected SignedData SEQUENCE");
	const sd = children(der, signedData.off, signedData.len);

	// sd[0] version, sd[1] digestAlgorithms SET, sd[2] encapContentInfo SEQUENCE,
	// sd[3] certificates [0] IMPLICIT (optional), sd[4] crls [1] (optional), sd[5] signerInfos SET
	let idx = 3;
	const certs: Uint8Array[] = [];
	if (idx < sd.length && (sd[idx].tag === 0xa0)) {
		// certificates [0] IMPLICIT SET OF Certificate (each is a DER cert SEQUENCE)
		const certSet = children(der, sd[idx].off, sd[idx].len);
		for (const c of certSet) certs.push(sl(der, c.off - c.hlen, c.hlen + c.len)); // full cert DER
		idx++;
	}
	// skip crls [1] if present
	if (idx < sd.length && sd[idx].tag === 0xa1) idx++;
	const signerInfosSet = sd[idx]; // SET OF SignerInfo
	const signerInfos = children(der, signerInfosSet.off, signerInfosSet.len);

	const encap = sd[2]; // encapContentInfo
	const encapChildren = children(der, encap.off, encap.len);
	const encapContentType = encapChildren[0].tag === 0x06 ? decodeOid(der, encapChildren[0].off, encapChildren[0].len) : "";

	const parsed: Pkcs7SignerInfo[] = [];
	for (const si of signerInfos) {
		parsed.push(parseSignerInfo(der, si));
	}
	return { encapContentType, certs, signerInfos: parsed };

	function parseSignerInfo(der: Uint8Array, si: TLV): Pkcs7SignerInfo {
		// SignerInfo ::= SEQUENCE { version, sid CHOICE, digestAlgorithm, signedAttrs [0] IMPLICIT SET OF, sigAlgorithm, sigValue OCTET STRING, unsignedAttrs [1] OPTIONAL }
		const f = children(der, si.off, si.len);
		// f[0] version, f[1] sid, f[2] digestAlgorithm, f[3] signedAttrs?, f[4] sigAlg, f[5] sigValue
		const digestAlgOid = decodeOidChild(der, f[2]);
		let signedAttrsIdx = 3;
		let signedAttrsDER: Uint8Array | null = null;
		if (f[3] && f[3].tag === 0xa0) {
			// Full [0] IMPLICIT TLV (tag+len+value); findAttribute / signedAttrsSignedBytes need it whole.
			signedAttrsDER = sl(der, f[3].off - f[3].hlen, f[3].hlen + f[3].len);
			signedAttrsIdx = 4;
		}
		const sigAlgOid = decodeOidChild(der, f[signedAttrsIdx]);
		const sigValue = getOctetString(der, f[signedAttrsIdx + 1]);

		// sid: issuerAndSerial (SEQUENCE 0x30) OR subjectKeyIdentifier ([0] 0x80)
		let sidIssuer: Uint8Array | null = null;
		let sidSerial: bigint | null = null;
		const sid = f[1];
		if (sid.tag === 0x30) {
			const iss = children(der, sid.off, sid.len);
			sidIssuer = sl(der, iss[0].off, iss[0].len); // issuer Name DER
			sidSerial = decodeInteger(der, iss[1].off, iss[1].len);
		}

		let messageDigest: Uint8Array | null = null;
		if (signedAttrsDER) {
			messageDigest = findAttribute(signedAttrsDER, OID.MESSAGE_DIGEST);
		}

		return { sigAlgOid: sigAlgOid, digestAlgOid, signedAttrsDER: signedAttrsDER ?? new Uint8Array(0), signature: sigValue, sidIssuer, sidSerial, messageDigest };
	}
}

function decodeOidChild(b: Uint8Array, t: TLV): string {
	// AlgorithmIdentifier is a SEQUENCE { OID, params }; tolerate both a bare OID
	// and a SEQUENCE wrapping one.
	const oidTlv = t.tag === 0x06 ? t : children(b, t.off, t.len)[0];
	if (!oidTlv || oidTlv.tag !== 0x06) throw new Error("expected OID");
	return decodeOid(b, oidTlv.off, oidTlv.len);
}

/** Read an OCTET STRING's content. Handles constructed/implicit forms minimally. */
function getOctetString(b: Uint8Array, t: TLV): Uint8Array {
	if (t.tag === 0x04) return sl(b, t.off, t.len);
	throw new Error(`expected OCTET STRING, got tag 0x${t.tag.toString(16)}`);
}

/** In the signedAttrs (a0 <len> <content>), find attribute <oid>'s first octet-string value.
 *  Returns the content bytes (for message-digest) or null. */
function findAttribute(signedAttrsDER: Uint8Array, oid: string): Uint8Array | null {
	// signedAttrs = a0 <len> <attrs> (IMPLICIT) OR a0 <len> 31 <len> <attrs> (EXPLICIT)
	const hdr = readTLV(signedAttrsDER, 0);
	if (hdr.tag !== 0xa0) return null;
	let contentOff = hdr.off;
	// If the content itself begins with a SET (0x31), treat it as explicit [0] wrapping a SET.
	const firstTag = signedAttrsDER[contentOff];
	let attrBytes: Uint8Array;
	if (firstTag === 0x31) {
		// explicit: signedAttrsDER = a0 <len> 31 <len> <attrs> -> attrs are the SET content
		const setTlv = readTLV(signedAttrsDER, contentOff);
		attrBytes = signedAttrsDER.slice(setTlv.off, setTlv.next);
	} else {
		// implicit: signedAttrsDER = a0 <len> <attrs> where attrs are Attribute SEQUENCEs directly
		attrBytes = signedAttrsDER.slice(contentOff, hdr.next);
	}
	// attrBytes = concatenation of Attribute SEQUENCEs
	const attrs = children(attrBytes, 0, attrBytes.length);
	for (const attr of attrs) {
		if (attr.tag !== 0x30) continue;
		const pair = children(attrBytes, attr.off, attr.len);
		if (pair.length < 2) continue;
		if (pair[0].tag !== 0x06) continue;
		const attrOid = decodeOid(attrBytes, pair[0].off, pair[0].len);
		if (attrOid === oid) {
			const valSet = pair[1]; // SET OF
			const vals = children(attrBytes, valSet.off, valSet.len);
			if (vals.length) return sl(attrBytes, vals[0].off, vals[0].len);
		}
	}
	return null;
}

/**
 * Compute the bytes that a PKCS#7 SignerInfo signature is computed over.
 * apksig signs the signedAttrs with the [0] tag (a0) re-tagged as a UNIVERSAL
 * SET (0x31); standard (explicit) jarsigner wraps a SET inside [0].
 */
export function signedAttrsSignedBytes(signedAttrsDER: Uint8Array): Uint8Array {
	if (signedAttrsDER.length === 0) return new Uint8Array(0);
	const hdr = readTLV(signedAttrsDER, 0);
	const contentOff = hdr.off;
	// implicit: a0 <len> <attrs> (attrs start with a SEQUENCE 0x30) -> re-tag a0->31
	if (signedAttrsDER[contentOff] !== 0x31) {
		const out = signedAttrsDER.slice();
		out[0] = 0x31;
		return out;
	}
	// explicit: a0 <len> 31 <len> <attrs> -> signature is over the inner SET
	const inner = readTLV(signedAttrsDER, contentOff);
	return signedAttrsDER.slice(inner.off, inner.next);
}

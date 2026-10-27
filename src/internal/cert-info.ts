/** Build a public {@link SignerInfo} from an X.509 certificate DER. */
import { parseX509Cert, OID, readTLV, children, decodeOid } from "./asn1.js";
import { sha1, sha256, hex } from "./binary.js";
import { SignerInfo, KeyAlgorithm } from "../types.js";

export async function certInfo(certDer: Uint8Array): Promise<SignerInfo> {
	const cert = parseX509Cert(certDer);
	const [fp256, fp1, spkiFp] = await Promise.all([
		sha256(certDer).then(hex),
		sha1(certDer).then(hex),
		sha256(cert.spki).then(hex),
	]);
	const { keyAlgorithm, keySize } = spkiInfo(cert.spki);
	return {
		certSha256: fp256,
		certSha1: fp1,
		publicKeySha256: spkiFp,
		subject: cert.subjectCN ?? null,
		keyAlgorithm,
		keySize,
	};
}

function spkiInfo(spki: Uint8Array): { keyAlgorithm: KeyAlgorithm; keySize: number } {
	// SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, subjectPublicKey BIT STRING }
	const root = readTLV(spki, 0); // SEQUENCE
	const fields = children(spki, root.off, root.len); // [AlgorithmIdentifier, BIT STRING]
	const algId = fields[0]; // AlgorithmIdentifier SEQUENCE
	const algFields = children(spki, algId.off, algId.len); // [OID, params]
	const algOid = algFields[0].tag === 0x06 ? decodeOid(spki, algFields[0].off, algFields[0].len) : "";

	if (algOid === OID.RSA_ENCRYPTION) {
		// BIT STRING content: 1 unused-bits byte, then RSAPublicKey { n, e }
		const bitString = fields[1];
		const contentOff = bitString.off; // after the BIT STRING tag+len
		const rsaPub = readTLV(spki, contentOff + 1);
		const rsaFields = children(spki, rsaPub.off, rsaPub.len);
		const nTlv = rsaFields[0]; // modulus INTEGER
		const nByteLen = nTlv.len;
		let bits = nByteLen * 8;
		// a leading 0x00 means the modulus is one bit shorter than the byte length
		if (spki[contentOff + 1 + rsaPub.hlen] === 0x00) bits -= 8;
		return { keyAlgorithm: "RSA", keySize: bits };
	}
	if (algOid === OID.EC_PUBLIC_KEY) {
		const curveOid =
			algFields.length >= 2 && algFields[1].tag === 0x06
				? decodeOid(spki, algFields[1].off, algFields[1].len)
				: "";
		return { keyAlgorithm: "EC", keySize: ecCurveBits(curveOid) };
	}
	return { keyAlgorithm: "unknown", keySize: 0 };
}

function ecCurveBits(curveOid: string): number {
	const m: Record<string, number> = {
		[OID.SECP256R1]: 256,
		[OID.SECP384R1]: 384,
		"1.3.132.0.35": 521,
	};
	return m[curveOid] ?? 0;
}

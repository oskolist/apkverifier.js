/**
 * APK Signature Scheme v1 (a.k.a. JAR signing) verification.
 *
 * Mirrors `V1SchemeVerifier`:
 *
 *  1. Parse `META-INF/MANIFEST.MF` and the `.SF` / `.RSA|.DSA|.EC` signature
 *     block files from the ZIP central directory.
 *  2. PKCS#7: for each SignerInfo, verify the signature. apksig signs
 *     over the signedAttrs (with the IMPLICIT `[0]` tag re-tagged to UNIVERSAL
 *     SET `0x31`) when signedAttrs are present *and* the `messageDigest`
 *     attribute equals SHA-x of the .SF file. apksigner (v1-on-top-of-v2/v3)
 *     emits SignerInfo **without** signedAttrs, so the signature is computed
 *     directly over the raw `.SF` file bytes and the messageDigest check is
 *     skipped — exactly `V1SchemeVerifier.verifySignerInfoAgainstSigFile`
 *     (lines 712-788).
 *  3. Verify the manifest's whole-file digest. The digest attribute lives in
 *     the **.SF main section** (`SHA-256-Digest-Manifest`), not in MANIFEST.MF.
 *  4. For every non-META-INF JAR entry: the manifest must carry a per-entry
 *     `SHA-256-Digest` equal to SHA-x of the entry's *uncompressed* data, and
 *     the entry must be listed in the .SF file (signature coverage). A
 *     mismatch here is what catches APK-body tampering.
 *
 * Digest algorithm selection follows apksig's JB-MR2+ "pick the strongest
 * present" rule (SHA-512 > SHA-384 > SHA-256 > SHA-1).
 */
import { ZipEntry, readEntry } from "./zip.js";
import { parsePkcs7, signedAttrsSignedBytes, oidToHash, type HashName, type X509Cert } from "./asn1.js";
import { oidToSigInfo, verifySig } from "./alg.js";
import { sha256, hex } from "./binary.js";
import { parseManifest, b64toBytes, type ManifestSection } from "./manifest.js";
import { parseX509Cert } from "./asn1.js";
import { certInfo } from "./cert-info.js";
import type { SchemeResult, SignerInfo } from "../types.js";

const MANIFEST_NAME = "META-INF/MANIFEST.MF";

// apksig JB-MR2+ strongest-first ordering for manifest/SF digests.
const JAR_HASHES: HashName[] = ["SHA-512", "SHA-384", "SHA-256", "SHA-1"];

const SUFFIX_ENTRY = "-Digest";
const SUFFIX_MANIFEST = "-Digest-Manifest";

function digestAttrName(hash: HashName, suffix: string): string {
	return (hash === "SHA-1" ? "SHA1" : hash) + suffix;
}

/** Pick the strongest per apksig's JB-MR2+ rule: first present attribute wins. */
function pickDigest(section: ManifestSection | undefined, suffix: string): { hash: HashName; bytes: Uint8Array } | null {
	if (!section) return null;
	for (const h of JAR_HASHES) {
		const v = section.attrs.get(digestAttrName(h, suffix));
		if (v !== undefined) return { hash: h, bytes: b64toBytes(v) };
	}
	return null;
}

function sigBlockEntry(e: ZipEntry): boolean {
	const n = e.name;
	return n.endsWith(".RSA") || n.endsWith(".DSA") || n.endsWith(".EC");
}

function isJarEntryDigestNeededInManifest(name: string): boolean {
	if (name.startsWith("META-INF/")) return false;
	return !name.endsWith("/");
}

async function digestFor(hash: HashName, data: Uint8Array): Promise<Uint8Array> {
	if (hash === "SHA-256") return sha256(data);
	const buf = await crypto.subtle.digest(hash as HashAlgorithmIdentifier, data as BufferSource);
	return new Uint8Array(buf as ArrayBuffer);
}

function equalBytes(a: Uint8Array | null, b: Uint8Array | null): boolean {
	if (!a || !b) return false;
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

interface SignerInfoLike {
	sidIssuer: Uint8Array | null;
	sidSerial: bigint | null;
}

export async function verifyV1(apk: Uint8Array, entries: ZipEntry[]): Promise<SchemeResult> {
	const errors: string[] = [];
	const byName = new Map<string, ZipEntry>();
	for (const e of entries) byName.set(e.name, e);

	// A v1 (JAR) signature is only "present" when the central directory actually
	// contains a signature block (META-INF/*.RSA|.DSA|.EC). When none exist the
	// APK is signed purely via v2/v3 — the norm for modern releases — and v1
	// being absent is expected, NOT an error. apksig reports this as "v1 not
	// present", not as a verification failure; a missing META-INF/MANIFEST.MF
	// with no v1 sig block must not be flagged (doing so wrongly marks clean
	// v2/v3-only APKs as unverified). See AGENTS.md ("v1 (JAR) gotchas") and the
	// regression tests in test/verify.test.ts ("v1 scheme error semantics").
	const sigBlockEntries = entries.filter(sigBlockEntry);
	if (sigBlockEntries.length === 0) {
		return { present: false, passed: false, signers: [], errors: [] };
	}

	// A signature block exists, so v1 IS present; a missing MANIFEST.MF now
	// indicates a genuinely broken/partial v1 signature.
	const manifestEntry = byName.get(MANIFEST_NAME);
	if (!manifestEntry) {
		return { present: true, passed: false, signers: [], errors: ["v1: signature block present but META-INF/MANIFEST.MF missing"] };
	}

	const manifestBytes = await readEntry(apk, manifestEntry);
	const manifest = parseManifest(manifestBytes);

	let p7VerifiedCount = 0;
	const certInfos: SignerInfo[] = [];
	let manifestDigestVerified = false;
	const sfEntryNames = new Set<string>();

	for (const sb of sigBlockEntries) {
		const dot = sb.name.lastIndexOf(".");
		const sfName = dot > 0 ? sb.name.slice(0, dot) + ".SF" : sb.name + ".SF";
		const sfEntry = byName.get(sfName);
		if (!sfEntry) {
			errors.push(`v1: no .SF file matches ${sb.name}`);
			continue;
		}
		const sfBytes = await readEntry(apk, sfEntry);
		const sigBlockBytes = await readEntry(apk, sb);

		// Parse the .SF file (it is a manifest-format file: main section + named sections).
		let sfManifest;
		try {
			sfManifest = parseManifest(sfBytes);
		} catch (e) {
			errors.push(`v1: .SF parse failed for ${sb.name}: ${(e as Error).message}`);
			continue;
		}

		// Manifest whole-file digest lives in the .SF main section ("SHA-*-Digest-Manifest").
		const manifestDigestAttr = pickDigest(sfManifest.main, SUFFIX_MANIFEST);
		if (manifestDigestAttr) {
			const actual = await digestFor(manifestDigestAttr.hash, manifestBytes);
			manifestDigestVerified = hex(actual) === hex(manifestDigestAttr.bytes);
			if (!manifestDigestVerified) errors.push("v1: manifest digest in .SF did not verify");
		} else {
			errors.push("v1: no manifest digest attribute in .SF");
		}

		// Record which JAR entries the .SF file covers (signing coverage).
		for (const k of sfManifest.entries.keys()) sfEntryNames.add(k);

		let p7;
		try {
			p7 = parsePkcs7(sigBlockBytes);
		} catch (e) {
			errors.push(`v1: PKCS#7 parse failed for ${sb.name}: ${(e as Error).message}`);
			continue;
		}
		if (p7.signerInfos.length === 0) {
			errors.push(`v1: no SignerInfo in ${sb.name}`);
			continue;
		}

		const parsedCerts: (X509Cert | null)[] = p7.certs.map((c) => {
			try {
				return parseX509Cert(c);
			} catch {
				return null;
			}
		});

		for (const si of p7.signerInfos) {
			const hash = oidToHash(si.digestAlgOid);
			if (!hash) {
				errors.push(`v1: unknown digest algorithm ${si.digestAlgOid}`);
				continue;
			}
			const info = oidToSigInfo(si.sigAlgOid, si.digestAlgOid);
			if (!info) {
				errors.push(`v1: unsupported signature algorithm ${si.sigAlgOid}`);
				continue;
			}

			// Match the SignerInfo sid (issuerAndSerial) to a cert; fall back to certs[0].
			let matchedDer: Uint8Array | null = null;
			let matchedParsed: X509Cert | null = null;
			const sid = si as SignerInfoLike;
			for (let i = 0; i < parsedCerts.length; i++) {
				const p = parsedCerts[i];
				if (!p) continue;
				if (
					equalBytes(sid.sidIssuer, p.issuer) &&
					sid.sidSerial !== null &&
					sid.sidSerial === p.serial
				) {
					matchedDer = p7.certs[i];
					matchedParsed = p;
					break;
				}
			}
			if (!matchedDer || !matchedParsed) {
				const i0 = parsedCerts.findIndex((p): p is X509Cert => p !== null);
				if (i0 >= 0) {
					matchedDer = p7.certs[i0];
					matchedParsed = parsedCerts[i0]!;
				}
			}
			if (!matchedDer || !matchedParsed) {
				errors.push("v1: signer certificate not found in SignedData");
				continue;
			}

			// apksig: signedAttrs present -> sig over (re-tagged) signedAttrs + messageDigest==SHA(SF);
			// apksigner: no signedAttrs -> sig over the .SF file bytes directly.
			const hasSignedAttrs = si.signedAttrsDER.length > 0;
			let signedBytes: Uint8Array;
			if (hasSignedAttrs) {
				if (!si.messageDigest) {
					errors.push("v1: SignerInfo missing messageDigest attribute");
					continue;
				}
				const sfDigest = await digestFor(hash, sfBytes);
				if (hex(sfDigest) !== hex(si.messageDigest)) {
					errors.push("v1: .SF message digest did not verify");
					continue;
				}
				signedBytes = signedAttrsSignedBytes(si.signedAttrsDER);
			} else {
				signedBytes = sfBytes;
			}

			try {
				const ok = await verifySig(info, matchedParsed.spki, si.signature, signedBytes);
				if (!ok) {
					errors.push("v1: SignerInfo signature did not verify");
					continue;
				}
				p7VerifiedCount++;
				certInfos.push(await certInfo(matchedDer));
			} catch (e) {
				errors.push(`v1: signature verify error: ${(e as Error).message}`);
			}
		}
	}

	const p7Verified = p7VerifiedCount > 0;

	// Per-entry manifest digests vs actual (uncompressed) zip entry data, plus
	// signature coverage (every non-META-INF entry must be listed in the .SF).
	let entryOk = true;
	let signedEntryCount = 0;
	for (const e of entries) {
		if (!isJarEntryDigestNeededInManifest(e.name)) continue;
		signedEntryCount++;
		const sec = manifest.entries.get(e.name);
		if (!sec) {
			errors.push(`v1: entry ${e.name} not listed in manifest`);
			entryOk = false;
			continue;
		}
		const d = pickDigest(sec, SUFFIX_ENTRY);
		if (!d) {
			errors.push(`v1: no digest for entry ${e.name}`);
			entryOk = false;
			continue;
		}
		const actual = await digestFor(d.hash, await readEntry(apk, e));
		if (hex(actual) !== hex(d.bytes)) {
			errors.push(`v1: digest mismatch for entry ${e.name} (tampered)`);
			entryOk = false;
		}
		if (!sfEntryNames.has(e.name)) {
			errors.push(`v1: entry ${e.name} not covered by .SF`);
			entryOk = false;
		}
	}
	if (signedEntryCount === 0) errors.push("v1: no signed JAR entries");

	const passed = p7Verified && manifestDigestVerified && entryOk && signedEntryCount > 0;
	return { present: true, passed, signers: certInfos, errors };
}

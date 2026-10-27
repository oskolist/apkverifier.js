/** Public, serializable result types for `verifyApk`. */

export type KeyAlgorithm = "RSA" | "EC" | "DSA" | "unknown";

export interface SignerInfo {
	/** SHA-256 fingerprint of the signer's X.509 certificate. */
	certSha256: string;
	/** SHA-1 fingerprint of the signer's X.509 certificate. */
	certSha1: string;
	/** SHA-256 fingerprint of the signer's public key (SPKI). */
	publicKeySha256: string;
	/** Best-effort subject Common Name (from the cert DN). */
	subject: string | null;
	/** Key algorithm family, derived from the cert's SPKI. */
	keyAlgorithm: KeyAlgorithm;
	/** Public key size in bits (RSA modulus / EC field size). */
	keySize: number;
}

export interface SchemeResult {
	/** Whether any signer block for this scheme was found. */
	present: boolean;
	/** Whether every present signer verified (signature + content digest). */
	passed: boolean;
	signers: SignerInfo[];
	/** Per-scheme error diagnostics, if any. */
	errors: string[];
}

export interface VerificationResult {
	/** `true` if the APK is intact per at least one verified signature scheme. */
	verified: boolean;
	schemes: {
		v1: SchemeResult;
		v2: SchemeResult;
		v3: SchemeResult;
	};
	/** Deduplicated signer cert SHA-256 digests across all *verified* schemes. */
	signerCertSha256: string[];
	/**
	 * `true` when an `expectedCertSha256` / `referenceApk` option was supplied
	 * and matched one of the verified signers. When no expectation was given,
	 * `true` (a verified APK is signed by *some* signer).
	 */
	authorVerified: boolean;
	/** Human-readable error if verification could not be performed. */
	error?: string;
}

export interface VerifyApkOptions {
	/** Expected signer certificate SHA-256 (hex, case-insensitive). */
	expectedCertSha256?: string;
	/** A trusted reference APK: signers must match its verified signers. */
	referenceApk?: Uint8Array;
}

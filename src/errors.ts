/** Error codes + typed error for `verifyApk`. */

export const VERIFY_ERROR = {
	BAD_ZIP: "BAD_ZIP",
	BAD_SIGNING_BLOCK: "BAD_SIGNING_BLOCK",
	NO_MANIFEST: "NO_MANIFEST",
	PARSE_ERROR: "PARSE_ERROR",
} as const;

export type VerifyErrorCode = keyof typeof VERIFY_ERROR;

/**
 * Thrown for fatal, unrecoverable problems (malformed APK / signing block) that
 * prevent any scheme from being checked. `verifyApk` surfaces these as the
 * `error` field of {@link VerificationResult} rather than throwing, so callers
 * can still inspect the per-scheme `present`/`passed` flags.
 */
export class ApkVerifyError extends Error {
	readonly code: VerifyErrorCode;
	constructor(code: VerifyErrorCode, message: string) {
		super(message);
		this.name = "ApkVerifyError";
		this.code = code;
	}
}

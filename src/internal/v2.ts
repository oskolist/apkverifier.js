/**
 * APK Signature Scheme v2 verification.
 *
 * v2 delegates to the shared signer-block parser in `signer.ts`; the only
 * scheme-specific detail is the `isV3 = false` flag passed to `parseSigners`.
 *
 * See `src/internal/signer.ts` for the SignedData/digest/signature framing.
 */
import { verifyScheme, V2Signer } from "./signer.js";
import { SchemeResult } from "../types.js";

export type { V2Signer };

/**
 * Verify the APK Signature Scheme v2 (a.k.a. "APK Signature Scheme v2").
 *
 *   apk        - raw APK bytes
 *   chunkData  - the v2 chunk payload (after the signing-block chunk header)
 *   blockStart - `blockStart` returned by `findSigningBlock`
 *   cdOff      - central-directory offset
 *   eocdOff    - End-of-Central-Directory record offset
 */
export function verifyV2(
	apk: Uint8Array,
	chunkData: Uint8Array,
	blockStart: number,
	cdOff: number,
	eocdOff: number,
): Promise<SchemeResult> {
	return verifyScheme(apk, chunkData, blockStart, cdOff, eocdOff, false);
}

/**
 * APK Signature Scheme v3 verification.
 *
 * v3 is structurally identical to v2 (same signer-block framing and the same
 * content-digest computation), except each signer record additionally carries
 * `minSdkVersion` / `maxSdkVersion`, and the signed-data additionally carries
 * them before the additional-attributes. The shared parser in `signer.ts`
 * handles this behind the `isV3 = true` flag.
 *
 * v3 also supports key rotation (a proof-of-rotation attribute, id
 * 0x3ba0668c... = PROOF_OF_ROTATION_ATTR_ID), which is recorded but not
 * enforced here — a signing cert that carries the trusted root still verifies.
 */
import { verifyScheme } from "./signer.js";
import { SchemeResult } from "../types.js";

export const PROOF_OF_ROTATION_ATTR_ID = 1000370060; // 0x3ba06f8c

export function verifyV3(
	apk: Uint8Array,
	chunkData: Uint8Array,
	blockStart: number,
	cdOff: number,
	eocdOff: number,
): Promise<SchemeResult> {
	return verifyScheme(apk, chunkData, blockStart, cdOff, eocdOff, true);
}

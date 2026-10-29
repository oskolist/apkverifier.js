/**
 * Usage:
 *   node scripts/extract-cert.cjs path/to/app.apk
 *
 * Verifies the APK with apkverifier and prints the signer certificate
 * SHA-256 (the "signature certificate hash"), SHA-1, key info, and the
 * per-scheme (v1/v2/v3) pass/present status.
 *
 * Should match the output of "apksigner verify --print-certs <apk_file>"
 */
"use strict";
const { readFileSync } = require("node:fs");
const { verifyApk } = require("../dist/index.js");

const path = process.argv[2];
if (!path) {
	console.error("usage: node scripts/extract-cert.cjs path/to/app.apk");
	process.exit(2);
}

const bytes = new Uint8Array(readFileSync(path));

verifyApk(bytes).then((res) => {
	console.log("=== apkverifier result ===");
	console.log("verified:", res.verified);
	if (res.error) console.log("error:", res.error);
	console.log("");

	console.log("Signer certificate hash(es):");
	for (const h of res.signerCertSha256) {
		console.log("  SHA-256:", h);
	}
	console.log("");

	for (const [name, scheme] of Object.entries(res.schemes)) {
		console.log(`${name}: present=${scheme.present} passed=${scheme.passed}`);
		if (scheme.errors.length) console.log("  errors:", scheme.errors.join("; "));
		for (const s of scheme.signers) {
			console.log(
				`  cert SHA-256=${s.certSha256}  SHA-1=${s.certSha1}  key=${s.keyAlgorithm}(${s.keySize})  subject=${s.subject ?? "n/a"}`
			);
		}
	}

	// The canonical "signature certificate hash" you are looking for:
	console.log("");
	console.log("signature certificate hash (SHA-256):", res.signerCertSha256[0] ?? "(none — no verified signer)");
});

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { verifyApk } from "../src/index.js";
import { ensureFixtures } from "./fixtures.js";

// apksigner is on PATH inside `nix develop`; the bare-shell node cannot see it,
// so spawn it via the shell wrapper and capture output.
function apksignVerify(apkPath: string, minSdk: number): OracleResult {
	let out = "";
	try {
		out = execFileSync(
			"apksigner",
			["verify", "--min-sdk-version", String(minSdk), "--max-sdk-version", "35", "--verbose", "--print-certs", "--in", apkPath],
			{ encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] },
		);
	} catch (e) {
		// apksigner exits non-zero when the APK does not verify, but still prints
		// its report to stdout.
		const err = e as { stdout?: string | Buffer };
		out = typeof err.stdout === "string" ? err.stdout : Buffer.from(err.stdout ?? "").toString("utf-8");
	}
	const line = (re: RegExp): string | null => {
		const m = out.match(re);
		return m ? m[1] : null;
	};
	const b = (re: RegExp): boolean => line(re) === "true";
	const v1 = b(/Verified using v1 scheme \(JAR signing\): (true|false)/);
	const v2 = b(/Verified using v2 scheme \(APK Signature Scheme v2\): (true|false)/);
	const v3 = b(/Verified using v3 scheme \(APK Signature Scheme v3\): (true|false)/);
	const certs: string[] = [];
	for (const m of out.matchAll(/Signer #\d+ certificate SHA-256 digest:\s*([0-9a-f]+)/g)) certs.push(m[1].toLowerCase());
	const overall = /^Verifies\s*$/m.test(out) ? "Verifies" : "DOES NOT VERIFY";
	return { overall, v1, v2, v3, certs };
}

interface OracleResult {
	overall: "Verifies" | "DOES NOT VERIFY";
	v1: boolean;
	v2: boolean;
	v3: boolean;
	certs: string[];
}

function readApk(path: string): Uint8Array {
	return new Uint8Array(readFileSync(path));
}

let fixtures: Awaited<ReturnType<typeof ensureFixtures>>;

before(async () => {
	fixtures = await ensureFixtures();
});

describe("APK Signature Scheme verification (oracle: apksigner verify)", () => {
	it("v1+v2+v3 RSA APK verifies on v1, v2, v3 and the signer cert matches", async () => {
		const bytes = readApk(fixtures.rsaApk);
		const oracle = apksignVerify(fixtures.rsaApk, fixtures.rsaMinSdk);
		const res = await verifyApk(bytes);
		assert.equal(res.verified, true);
		assert.deepEqual(res.schemes.v1.passed, oracle.v1);
		assert.deepEqual(res.schemes.v2.passed, oracle.v2);
		assert.deepEqual(res.schemes.v3.passed, oracle.v3);
		assert.deepEqual(res.signerCertSha256, oracle.certs);
		assert.equal(res.authorVerified, true);
	});

	it("v1+v2+v3 EC APK verifies on v1, v2, v3 and the signer cert matches", async () => {
		const bytes = readApk(fixtures.ecApk);
		const oracle = apksignVerify(fixtures.ecApk, fixtures.ecMinSdk);
		const res = await verifyApk(bytes);
		assert.equal(res.verified, true);
		assert.deepEqual(res.schemes.v1.passed, oracle.v1);
		assert.deepEqual(res.schemes.v2.passed, oracle.v2);
		assert.deepEqual(res.schemes.v3.passed, oracle.v3);
		assert.deepEqual(res.signerCertSha256, oracle.certs);
	});

	it("v2-only RSA APK: v1 absent, v2 passes, v3 absent", async () => {
		const bytes = readApk(fixtures.v2onlyRsaApk);
		const oracle = apksignVerify(fixtures.v2onlyRsaApk, fixtures.v2onlyMinSdk);
		const res = await verifyApk(bytes);
		assert.equal(res.verified, true);
		assert.equal(res.schemes.v1.present, false);
		assert.equal(res.schemes.v1.passed, false);
		assert.deepEqual(res.schemes.v2.passed, oracle.v2);
		assert.equal(res.schemes.v3.present, false);
		assert.deepEqual(res.signerCertSha256, oracle.certs);
	});

	it("v2-only EC APK: v1 absent, v2 passes, v3 absent", async () => {
		const bytes = readApk(fixtures.v2onlyEcApk);
		const oracle = apksignVerify(fixtures.v2onlyEcApk, fixtures.v2onlyMinSdk);
		const res = await verifyApk(bytes);
		assert.equal(res.verified, true);
		assert.equal(res.schemes.v1.present, false);
		assert.deepEqual(res.schemes.v2.passed, oracle.v2);
		assert.equal(res.schemes.v3.present, false);
	});

	for (const label of ["tampered-rsa", "tampered-ec"] as const) {
		it(`tampered ${label} APK: overall verify fails and v2/v3 digest checks fail`, async () => {
			const path = label === "tampered-rsa" ? fixtures.tamperedRsaApk : fixtures.tamperedEcApk;
			const bytes = readApk(path);
			const oracle = apksignVerify(path, fixtures.rsaMinSdk);
			assert.equal(oracle.overall, "DOES NOT VERIFY");
			const res = await verifyApk(bytes);
			assert.equal(res.verified, false);
			assert.equal(res.schemes.v2.passed, false);
			assert.equal(res.schemes.v3.passed, false);
		});
	}

	it("expectedCertSha256 option author-verifies the matching signer and rejects others", async () => {
		// matching expected cert → authorVerified true
		const ok = await verifyApk(readApk(fixtures.rsaApk), { expectedCertSha256: fixtures.rsaCertSha256 });
		assert.equal(ok.authorVerified, true);
		// mismatched expected cert → authorVerified false (even though APK itself is valid)
		const bad = await verifyApk(readApk(fixtures.rsaApk), { expectedCertSha256: fixtures.ecCertSha256 });
		assert.equal(bad.authorVerified, false);
		// tampered apk with expected cert → authorVerified false
		const tampered = await verifyApk(readApk(fixtures.tamperedRsaApk), { expectedCertSha256: fixtures.rsaCertSha256 });
		assert.equal(tampered.authorVerified, false);
	});

	it("referenceApk option author-verifies against a trusted reference", async () => {
		const ref = readApk(fixtures.rsaApk);
		const same = await verifyApk(readApk(fixtures.rsaApk), { referenceApk: ref });
		assert.equal(same.authorVerified, true);
		// EC reference has a different signer cert → author mismatch
		const other = await verifyApk(readApk(fixtures.rsaApk), { referenceApk: readApk(fixtures.ecApk) });
		assert.equal(other.authorVerified, false);
	});
});

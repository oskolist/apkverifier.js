/**
 * Test-fixture generator.
 *
 * Builds a small, deterministic set of signed APKs (RSA + EC, v1+v2+v3; a v2-only
 * RSA APK; and tampered copies) under `test/_apk/` using `zip`, `openssl`, and
 * `apksigner` (on PATH inside `nix develop`). These are the reference fixtures
 * that both the library and `apksigner verify` (the oracle) run over.
 *
 * Generated artifacts are gitignored. Re-run by deleting `test/_apk/`.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";

const DIR = join(import.meta.dirname, "_apk");

const MANIFEST = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app" android:versionCode="1" android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="35" />
    <application android:label="@string/app_name" />
</manifest>
`;

const STRINGS = `<?xml version="1.0" encoding="utf-8"?>
<resources><string name="app_name">App</string></resources>
`;

// A minimal but *valid* DEX (035): enough bytes that apksigner/zip are happy and
// the v1 manifest lists it. We don't execute it; only sign & verify it.
const DEX = minimalDex();

function minimalDex(): Uint8Array {
	// dex\n035\0 header (112 bytes) + a single empty class_def-ish tail. The
	// checksum/signature fields are left zero; apksigner does not validate DEX
	// internals, only the byte signatures over the whole APK.
	const b = new Uint8Array(128);
	const magic = new TextEncoder().encode("dex\n035\x00");
	b.set(magic, 0);
	// file size (bytes 32-35, LE)
	const sz = b.length;
	b[32] = sz & 0xff;
	b[33] = (sz >>> 8) & 0xff;
	b[34] = (sz >>> 16) & 0xff;
	b[35] = (sz >>> 24) & 0xff;
	// header size (40) at bytes 64-67
	b[64] = 40 & 0xff;
	b[65] = (40 >>> 8) & 0xff;
	b[66] = (40 >>> 16) & 0xff;
	b[67] = (40 >>> 24) & 0xff;
	// string_ids_size/off (72-79) = 0
	// etc. all zero is fine for our purpose.
	return b;
}

function sh(cmd: string, args: string[], opts: { cwd?: string } = {}): void {
	execFileSync(cmd, args, { ...opts, stdio: "pipe", encoding: "utf-8" });
}

/** SHA-256 of an X.509 cert (DER), matching `apksigner verify --print-certs`. */
function certSha256FromPem(pemFile: string): string {
	const der = execFileSync("openssl", ["x509", "-in", pemFile, "-outform", "DER"]);
	return createHash("sha256").update(der).digest("hex");
}

export interface Fixtures {
	dir: string;
	/** RSA (v1+v2+v3) APK path. */
	rsaApk: string;
	ecApk: string;
	/** v2-only APK paths (minSdk 24). */
	v2onlyRsaApk: string;
	v2onlyEcApk: string;
	/** Tampered copies (minSdk 21, v1+v2+v3). */
	tamperedRsaApk: string;
	tamperedEcApk: string;
	/** Expected signer cert SHA-256 fingerprints (hex, lower). */
	rsaCertSha256: string;
	ecCertSha256: string;
	/** minSdkVersion to feed the `apksigner verify` oracle for each fixture. */
	rsaMinSdk: number;
	ecMinSdk: number;
	v2onlyMinSdk: number;
}

export function ensureFixtures(): Fixtures {
	mkdirSync(DIR, { recursive: true });
	const w = (name: string, buf: Uint8Array | string) => writeFileSync(join(DIR, name), buf);
	const rsaKey = join(DIR, "rsa.key");
	const rsaPk8 = join(DIR, "rsa.pk8");
	const rsaPem = join(DIR, "rsa.pem");
	const ecKey = join(DIR, "ec.key");
	const ecPk8 = join(DIR, "ec.pk8");
	const ecPem = join(DIR, "ec.pem");

	if (!existsSync(rsaPem)) {
		sh("openssl", ["genrsa", "-out", rsaKey, "2048"]);
		sh("openssl", ["pkcs8", "-topk8", "-nocrypt", "-in", rsaKey, "-outform", "DER", "-out", rsaPk8]);
		sh("openssl", ["req", "-new", "-x509", "-key", rsaKey, "-out", rsaPem, "-days", "3650", "-subj", "/CN=Test RSA"]);
		sh("openssl", ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", ecKey]);
		sh("openssl", ["pkcs8", "-topk8", "-nocrypt", "-in", ecKey, "-outform", "DER", "-out", ecPk8]);
		sh("openssl", ["req", "-new", "-x509", "-key", ecKey, "-out", ecPem, "-days", "3650", "-subj", "/CN=Test EC"]);
	}
	const rsaCertSha256 = certSha256FromPem(rsaPem);
	const ecCertSha256 = certSha256FromPem(ecPem);

	const manifestPath = join(DIR, "AndroidManifest.xml");
	const dexPath = join(DIR, "classes.dex");
	const stringsPath = join(DIR, "strings.xml");
	w("AndroidManifest.xml", MANIFEST);
	w("classes.dex", DEX);
	w("strings.xml", STRINGS);

	const baseApk = join(DIR, "base.apk");
	// Stored (-0), no compression, no extra dir entries, no extra zip metadata.
	sh("zip", ["-q", "-X", "-D", "-0", baseApk, "AndroidManifest.xml", "classes.dex", "strings.xml"], { cwd: DIR });

	const rsaApk = join(DIR, "v1v2v3-rsa.apk");
	const ecApk = join(DIR, "v1v2v3-ec.apk");
	const v2onlyRsaApk = join(DIR, "v2only-rsa.apk");
	const v2onlyEcApk = join(DIR, "v2only-ec.apk");
	const tamperedRsaApk = join(DIR, "tampered-rsa.apk");
	const tamperedEcApk = join(DIR, "tampered-ec.apk");

	if (!existsSync(rsaApk)) {
		sh("apksigner", ["sign", "--key", rsaPk8, "--cert", rsaPem, "--min-sdk-version", "21", "--max-sdk-version", "35", "--out", rsaApk, baseApk]);
	}
	if (!existsSync(ecApk)) {
		sh("apksigner", ["sign", "--key", ecPk8, "--cert", ecPem, "--min-sdk-version", "21", "--max-sdk-version", "35", "--out", ecApk, baseApk]);
	}
	if (!existsSync(v2onlyRsaApk)) {
		sh("apksigner", ["sign", "--key", rsaPk8, "--cert", rsaPem, "--min-sdk-version", "24", "--max-sdk-version", "35", "--v1-signing-enabled", "false", "--v3-signing-enabled", "false", "--out", v2onlyRsaApk, baseApk]);
	}
	if (!existsSync(v2onlyEcApk)) {
		sh("apksigner", ["sign", "--key", ecPk8, "--cert", ecPem, "--min-sdk-version", "24", "--max-sdk-version", "35", "--v1-signing-enabled", "false", "--v3-signing-enabled", "false", "--out", v2onlyEcApk, baseApk]);
	}

	// Tampered copies: flip a byte inside classes.dex DATA (within the pre-block
	// region) so v1 entry digests and v2/v3 content digests both break, while the
	// signing block / CD / EOCD stay structurally intact.
	for (const [src, dst] of [
		[src2bytes(rsaApk), tamperedRsaApk],
		[src2bytes(ecApk), tamperedEcApk],
	] as const) {
		if (!existsSync(dst)) writeFileSync(dst, tamper(src));
	}

	return {
		dir: DIR,
		rsaApk,
		ecApk,
		v2onlyRsaApk,
		v2onlyEcApk,
		tamperedRsaApk,
		tamperedEcApk,
		rsaCertSha256,
		ecCertSha256,
		rsaMinSdk: 21,
		ecMinSdk: 21,
		v2onlyMinSdk: 24,
	};
}

function src2bytes(path: string): Uint8Array {
	return new Uint8Array(readFileSync(path));
}

/** Flip a byte inside classes.dex's local data to simulate tampering. */
function tamper(apk: Uint8Array): Uint8Array {
	// Locate classes.dex local file header via the central directory is overkill;
	// scan for the local header signature + "classes.dex" name (stored entry).
	const sig = new Uint8Array([0x50, 0x4b, 0x03, 0x04]);
	outer: for (let i = 0; i + 4 <= apk.length; i++) {
		if (apk[i] !== sig[0] || apk[i + 1] !== sig[1] || apk[i + 2] !== sig[2] || apk[i + 3] !== sig[3]) continue;
		const nameLen = apk[i + 26] | (apk[i + 27] << 8);
		const extraLen = apk[i + 28] | (apk[i + 29] << 8);
		const name = new TextDecoder().decode(apk.subarray(i + 30, i + 30 + nameLen));
		if (name === "classes.dex") {
			const dataOff = i + 30 + nameLen + extraLen;
			const buf = apk.slice();
			buf[dataOff] = buf[dataOff] ^ 0xff; // flip first data byte
			return buf;
		}
		continue outer;
	}
	// Fallback: flip a byte near offset 0x1000 (inside the first entry's data).
	const buf = apk.slice();
	buf[4096] = buf[4096] ^ 0xff;
	return buf;
}

export { minimalDex };

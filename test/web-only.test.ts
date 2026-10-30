/**
 * Regression guard: the library in `src/` MUST stay Web-API-surface-only.
 *
 * `apkverifier` targets Node 22 *and* browsers by relying solely on standardized
 * Web platform APIs (`crypto.subtle`, `DecompressionStream`, `DataView`, …). It
 * must never import a Node built-in (`node:fs`, `node:crypto`, `node:path`, …)
 * or touch Node's `Buffer`/`process` — those are confined to the test harness,
 * which legitimately shells out to native tools (`apksigner`, `zip`, `openssl`)
 * and computes reference digests via `node:crypto`.
 *
 * This test enforces that boundary so the single code path stays live in both
 * environments, and asserts that the WebCrypto global actually produces digests
 * equal to a Node `crypto` oracle (i.e. the "browser environment" is exercised
 * and agrees with the Node reference).
 *
 * NOTE: this file deliberately does NOT call `ensureFixtures()` (unlike
 * verify.test.ts) so it cannot race on the shared `test/_apk/` dir when both
 * suites run concurrently under `node --test`. The WebCrypto-equivalence check
 * instead uses the real, pre-existing SlipStream APK (skipped if absent).
 */
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { verifyApk } from "../src/index.js";

const ROOT = resolve(import.meta.dirname, "..");
const SRC_DIR = resolve(ROOT, "src");
const DIST_BROWSER_DIR = resolve(ROOT, "dist-browser");

// Known-good signer cert for the in-repo SlipStream APK, taken from
// `apksigner verify --print-certs` (and confirmed by an ESM/WebCrypto smoke run).
// Used as the oracle so this test needs no generated fixtures / no `before` hook.
const SLIPNET_APK = resolve(ROOT, "SlipNet-v2.5.5-full-release-arm64-v8a.apk");
const SLIPNET_CERT_SHA256 = "daf191df7ace75ac24f8b13fdceb39e17ebb4b23fa336ccae8d423a2ace73402";

function rel(p: string): string {
	return p.startsWith(ROOT) ? p.slice(ROOT.length + 1) : p;
}

/** All `import … from "m"` / `import "m"` / `export … from "m"` specifiers. */
function importSpecifiers(src: string): string[] {
	const specs: string[] = [];
	const re = /\b(?:import|export)\s+(?:[^'";]+?\s+from\s+)?["']([^"']+)["']/g;
	let m: RegExpExecArray | null;
	while ((m = re.exec(src)) !== null) specs.push(m[1]);
	return specs;
}

const NODE_BUILTINS = [
	"fs", "path", "crypto", "os", "process", "stream", "buffer", "zlib",
	"util", "child_process", "events", "http", "https", "net", "tls",
];

/** Patterns forbidden in `src/` (and in the ESM build). */
const FORBIDDEN = {
	require: /\brequire\s*\(/,
	process: /\bprocess\b/,
	nodeBuiltin: new RegExp(`\\bnode:(?:${NODE_BUILTINS.join("|")})\\b`),
	requireBuiltin: new RegExp(`require\\s*\\(\\s*["'](?:node:)?(?:${NODE_BUILTINS.join("|")})["']\\s*\\)`),
	nodeBuffer: /\bBuffer\b/, // word-boundary: won't match ArrayBuffer / BufferSource
};

function walk(dir: string, ext: string): string[] {
	const out: string[] = [];
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const p = resolve(dir, entry.name);
		if (entry.isDirectory()) out.push(...walk(p, ext));
		else if (entry.name.endsWith(ext)) out.push(p);
	}
	return out;
}

describe("library source is Web-API-surface-only", () => {
	const files = walk(SRC_DIR, ".ts");
	assert.ok(files.length > 0, "expected source files in src/");

	for (const file of files) {
		const src = readFileSync(file, "utf-8");

		it(`${rel(file)}: only relative import specifiers (no Node/npm deps)`, () => {
			for (const spec of importSpecifiers(src)) {
				assert.ok(
					spec.startsWith("."),
					`${rel(file)} imports a non-relative module "${spec}" — a Node built-in or npm dependency was detected.`,
				);
			}
		});

		it(`${rel(file)}: no Node-only globals (require/process/Buffer/node:*)`, () => {
			for (const [name, re] of Object.entries(FORBIDDEN)) {
				if (re.test(src)) assert.fail(`${rel(file)} uses Node-only API "${name}" — forbidden in src/`);
			}
		});
	}
});

describe("dist-browser build is native ESM and Node-free", () => {
	if (!existsSync(resolve(DIST_BROWSER_DIR, "index.js"))) {
		it.skip("dist-browser/ not present — run `npm run build:browser` to exercise this guard");
		return;
	}

	const files = walk(DIST_BROWSER_DIR, ".js");
	assert.ok(files.length > 0, "expected emitted .js files in dist-browser/");

	for (const file of files) {
		const body = readFileSync(file, "utf-8");
		it(`${rel(file)}: native ESM (no CommonJS require) and no Node built-ins`, () => {
			assert.equal(/require\s*\(/.test(body), false, `${rel(file)} is CommonJS (contains require())`);
			assert.ok(/export\b/.test(body) || /import\b/.test(body), `${rel(file)} has no ESM export/import`);
			for (const [name, re] of Object.entries(FORBIDDEN)) {
				if (re.test(body)) assert.fail(`${rel(file)} references Node-only API "${name}"`);
			}
		});
	}
});

describe("WebCrypto path agrees with the node:crypto oracle", () => {
	it("crypto.subtle (WebCrypto global) SHA-256 matches node:crypto createHash", async () => {
		assert.ok(globalThis.crypto?.subtle, "expected globalThis.crypto.subtle (WebCrypto) to be available");
		const msg = new TextEncoder().encode("apkverifier browser-path sanity check");
		// WebCrypto — exactly what a browser calls:
		const web = new Uint8Array(await crypto.subtle.digest("SHA-256", msg));
		// Node oracle (different implementation, same spec):
		const node = new Uint8Array(createHash("sha256").update(Buffer.from(msg)).digest());
		assert.deepEqual(web, node, "WebCrypto and node:crypto disagreed on SHA-256");
	});

	const slipNetIt = existsSync(SLIPNET_APK) ? it : it.skip;
	slipNetIt("verifyApk (WebCrypto engine) extracts the known SlipStream signer cert", async () => {
		const bytes = new Uint8Array(readFileSync(SLIPNET_APK));
		const res = await verifyApk(bytes);
		assert.equal(res.verified, true);
		// The cert digest is produced by crypto.subtle.digest inside the library;
		// it must equal the apksigner/oracle value for this real APK.
		assert.equal(res.signerCertSha256[0], SLIPNET_CERT_SHA256, "WebCrypto-derived cert != oracle");
		assert.equal(res.schemes.v2.passed, true);
		assert.equal(res.schemes.v1.present, false, "SlipStream is v2-only (no v1 sig block)");
	});
});

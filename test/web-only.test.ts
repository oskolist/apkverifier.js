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
 */
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { verifyApk } from "../src/index.js";
import { ensureFixtures } from "./fixtures.js";

const ROOT = join(import.meta.dirname, "..");
const SRC_DIR = join(ROOT, "src");
const DIST_BROWSER_DIR = join(ROOT, "dist-browser");

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
		const p = join(dir, entry.name);
		if (entry.isDirectory()) out.push(...walk(p, ext));
		else if (entry.name.endsWith(ext)) out.push(p);
	}
	return out;
}

let fixtures: Awaited<ReturnType<typeof ensureFixtures>>;
before(async () => {
	fixtures = await ensureFixtures();
});

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
	if (!existsSync(join(DIST_BROWSER_DIR, "index.js"))) {
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

	it("verifyApk on a fixture matches the apksigner-derived cert via the WebCrypto engine", async () => {
		const bytes = new Uint8Array(readFileSync(fixtures.rsaApk));
		const res = await verifyApk(bytes);
		// fixtures.rsaCertSha256 comes from `openssl x509 -outform DER | createHash("sha256")` (Node oracle).
		// The library computes the same digest through crypto.subtle.digest — they must agree.
		assert.equal(res.verified, true);
		assert.ok(res.signerCertSha256.length > 0);
		assert.equal(
			res.signerCertSha256[0],
			fixtures.rsaCertSha256,
			"cert SHA-256 from WebCrypto != node oracle",
		);
		assert.equal(res.schemes.v2.passed, true);
	});
});

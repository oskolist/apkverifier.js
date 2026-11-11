/**
 * Regression guard for `inflateRaw` backpressure handling.
 *
 * `DecompressionStream` applies backpressure on its writable side, so writing a
 * whole multi-megabyte entry before draining the readable side deadlocks. Real
 * APKs hit this on `classes.dex` (megabytes of compressed data), which made
 * `verifyApk` hang forever instead of resolving. This test round-trips a payload
 * large enough to exceed the stream's internal queue.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { deflateRawSync } from "node:zlib";
import { inflateRaw } from "../src/internal/binary.js";

describe("inflateRaw", () => {
	it("decompresses a large deflated entry without deadlocking", async () => {
		// The deadlock is on the *compressed* side: the writer must be given
		// more bytes than the stream's queue can hold. Use a deterministic
		// pseudo-random fill so the payload stays incompressible (the deflated
		// form is ~8 MiB) and the input is not just a tiny literal.
		const original = new Uint8Array(8 * 1024 * 1024);
		let state = 0x9e3779b9;
		for (let i = 0; i < original.length; i++) {
			state ^= state << 13;
			state ^= state >>> 17;
			state ^= state << 5;
			original[i] = state & 0xff;
		}
		const compressed = new Uint8Array(deflateRawSync(original));
		assert.ok(compressed.length > 4 * 1024 * 1024, "payload must exceed the stream queue");

		const out = await inflateRaw(compressed);
		assert.equal(out.length, original.length);
		assert.deepEqual(out, original);
	});

	it("rejects (rather than hangs) on corrupt deflate data", async () => {
		const corrupt = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
		await assert.rejects(inflateRaw(corrupt));
	});
});

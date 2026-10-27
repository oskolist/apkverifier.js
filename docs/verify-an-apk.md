# How to verify an APK

This guide shows the most common use of `apkverifier`: given an APK's bytes,
verify that it is **intact** (i.e. it has not been modified since it was signed)
and inspect *which* schemes verified and *who* signed it.

## Load the APK as bytes

`verifyApk` takes a `Uint8Array`. In Node you read the file; in a browser you
read a `Blob`/`File`/fetch response into an `ArrayBuffer`.

### Node

```ts
import { readFileSync } from "node:fs";
import { verifyApk } from "apkverifier";

const apk = new Uint8Array(readFileSync("app-release.apk"));
const result = await verifyApk(apk);

console.log(result.verified);           // true | false  (intact?)
console.log(result.signerCertSha256); // ["f7387c306b…"]
```

### Browser

```ts
import { verifyApk } from "apkverifier";

const buf = await (await fetch("/app-release.apk")).arrayBuffer();
const result = await verifyApk(new Uint8Array(buf));
console.log(result.verified, result.signerCertSha256);
```

## Read the result

`verifyApk` resolves to a `VerificationResult`:

```ts
interface VerificationResult {
  // true iff the APK is intact according to at least one verified scheme.
  verified: boolean;

  // Per-scheme detail. v1 (JAR), v2, v3.
  schemes: {
    v1: SchemeResult;
    v2: SchemeResult;
    v3: SchemeResult;
  };

  // Deduplicated SHA-256 fingerprints of the signer certificates across the
  // schemes that passed. Use these to recognise a known author.
  signerCertSha256: string[];

  // Whether the (optional) expected-author check passed.
  authorVerified: boolean;

  // Only set when the APK itself could not be parsed (malformed ZIP, etc.).
  error?: string;
}

interface SchemeResult {
  present: boolean;  // a signer block for this scheme was found
  passed: boolean;   // every present signer verified (signature + content digest)
  signers: SignerInfo[];
  errors: string[];  // diagnostics for this scheme, if any
}
```

### Example: inspect every scheme

```ts
const r = await verifyApk(apk);
for (const [name, s] of Object.entries(r.schemes)) {
  console.log(`${name}: present=${s.present} passed=${s.passed}`);
  for (const signer of s.signers) {
    console.log(`  cert=${signer.certSha256} key=${signer.keyAlgorithm}/${signer.keySize}`);
  }
}
// signerCertSha256 contains the fingerprints of signers that PASSED.
```

## Interpreting the outcomes

| `verified` | Meaning |
|------------|---------|
| `true` | The APK bytes are intact per **at least one** of v1/v2/v3. |
| `false` | The APK was modified after signing (content digest mismatch), or the ZIP/signing block is malformed. Inspect `schemes.*.errors` and the top-level `error`. |

A common, secure posture is the **highest scheme that verifies**:

- An APK signed with v2/v3 only (the modern default) verifies via `v2`/`v3`.
- An APK signed with v1 only (legacy) verifies via `v1`.
- A tampered APK reports `verified: false` with `v2`/`v3` `passed: false`
  (the content digest no longer matches).

> **Note on `present` vs `passed`:** `present: true, passed: true` means the
> scheme's block was found *and* verified. `present: true, passed: false` means
> the block was found but verification **failed** (e.g. tampering).
> `present: false` means the scheme's signer block simply isn't in the APK (e.g.
> a v2-only APK has no v1 `MANIFEST.MF`). See
> [Signature schemes](./signature-schemes.md) for details.

## What "signed by a known author" adds

Integrity (`verified: true`) proves the APK is unchanged — but not which key
signed it. To confirm the signer is the *expected author*, use
[`expectedCertSha256` or `referenceApk`](./verify-the-signer.md).

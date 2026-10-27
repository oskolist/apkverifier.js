# API reference

TypeScript type definitions (also published as `dist/*.d.ts`).

```ts
import { verifyApk } from "apkverifier";
```

## `verifyApk`

```ts
function verifyApk(apk: Uint8Array, opts?: VerifyApkOptions): Promise<VerificationResult>;
```

Verifies an APK's integrity and signer across APK Signature Schemes v1, v2, and
v3.

- `apk` — the full raw bytes of the `.apk` file (a `Uint8Array`). In Node this is
  typically `new Uint8Array(fs.readFileSync(path))`; in a browser, an
  `ArrayBuffer` wrapped in a `Uint8Array`.
- `opts` — optional. See [`VerifyApkOptions`](#verifyapkoptions).

Returns a `Promise<VerificationResult>`. It does **not** throw for malformed or
tampered APKs; fatal problems (e.g. an unparseable ZIP) are reported via the
`error` field and the per-scheme `errors`, with `verified: false`.

### `VerifyApkOptions`

```ts
interface VerifyApkOptions {
  /** Expected signer certificate SHA-256, hex (case-insensitive, ignores non-hex). */
  expectedCertSha256?: string;
  /** A trusted reference APK (Uint8Array). The candidate must share a verified signer. */
  referenceApk?: Uint8Array;
}
```

Only one of `expectedCertSha256` / `referenceApk` should be supplied. When
neither is given, `authorVerified` defaults to `verified` (a verified APK is
signed by *some* signer).

## Result types

### `VerificationResult`

```ts
interface VerificationResult {
  /** true if the APK is intact per at least one verified signature scheme. */
  verified: boolean;

  /** Per-scheme status. */
  schemes: {
    v1: SchemeResult; // JAR signing (META-INF/MANIFEST.MF + .SF + PKCS#7)
    v2: SchemeResult; // APK Signature Scheme v2
    v3: SchemeResult; // APK Signature Scheme v3 (rotation-aware)
  };

  /** Deduplicated SHA-256 fingerprints of signers across the schemes that passed. */
  signerCertSha256: string[];

  /**
   * true when an expected-author option was supplied and matched one of the
   * verified signers; otherwise equals `verified` (no expectation given).
   */
  authorVerified: boolean;

  /** Set only on fatal, unrecoverable errors (e.g. malformed ZIP). */
  error?: string;
}
```

### `SchemeResult`

```ts
interface SchemeResult {
  /** A signer block for this scheme was found in the APK. */
  present: boolean;
  /** Every present signer verified (signature + content digest). */
  passed: boolean;
  /** Verified signer metadata for this scheme (only populated when passed). */
  signers: SignerInfo[];
  /** Per-scheme diagnostic messages (verification failures, parse errors, …). */
  errors: string[];
}
```

### `SignerInfo`

```ts
type KeyAlgorithm = "RSA" | "EC" | "DSA" | "unknown";

interface SignerInfo {
  /** SHA-256 fingerprint of the signer's X.509 certificate (lowercase hex). */
  certSha256: string;
  /** SHA-1 fingerprint of the signer's X.509 certificate (lowercase hex). */
  certSha1: string;
  /** SHA-256 fingerprint of the signer's SubjectPublicKeyInfo (SPKI). */
  publicKeySha256: string;
  /** Best-effort subject (Common Name from the cert DN), or null. */
  subject: string | null;
  /** Key algorithm family (RSA / EC / DSA / unknown). */
  keyAlgorithm: KeyAlgorithm;
  /** Public key size in bits (RSA modulus bits; EC field size). */
  keySize: number;
}
```

## Environment requirements

- **Node.js ≥ 22** (uses `crypto.subtle`, `DecompressionStream('deflate-raw')`).
- **Modern browsers** with `crypto.subtle` and `DecompressionStream`.
- No optional/peer dependencies. The library bundle imports only the Web
  platform APIs — no Node built-ins, `pako`, or `node-forge`.

## Error handling

`verifyApk` never throws for a bad or tampered APK; inspect the result:

```ts
const res = await verifyApk(bytes);
if (res.error) {
  // Fatal: the APK couldn't be structurally verified (e.g. "bad ZIP: …").
  console.error("unrecoverable:", res.error);
}
if (!res.verified) {
  // Integrity failure (or an unparseable block).
  console.error("not verified", {
    v1: res.schemes.v1.errors,
    v2: res.schemes.v2.errors,
    v3: res.schemes.v3.errors,
  });
}
```

## Accuracy

Library results are cross-checked against
`apksigner verify --min-sdk-version N --max-sdk-version 35 --verbose
--print-certs` (the reference oracle from `com.android.apksig`) for RSA and EC
keys, including tampered-APK rejection. See the project
[`AGENTS.md`](../AGENTS.md) and [`src/AGENTS.md`](../src/AGENTS.md) for the
exact algorithm correspondence.

# apkverifier.js

A tiny, dependency-free **pure-TypeScript** library that verifies the
author/signer of an Android `.apk` file. Given an APK's bytes it tells you
whether the APK is intact (unmodified since it was signed) and *who* signed it,
by checking all three APK signature schemes and cross-checking against a known
signer certificate or a trusted reference APK.

- Supports **APK Signature Scheme v1** (JAR signing), **v2**, and **v3**.
- Runs unchanged on **Node.js ≥ 22** and **modern browsers**.
- **Zero runtime dependencies** — only the Web platform APIs (`crypto.subtle`, `DecompressionStream('deflate-raw')`).
- Typed results, per-scheme detail, signer certificate fingerprints (SHA-256/SHA-1) and public-key fingerprints, and an `authorVerified` flag.
- Cross-checked against Android's [`apksigner verify`](https://developer.android.com/build/building-cmdline-analyze-apks) (the reference oracle) for RSA and EC keys.

## Install

Currently it's not published to npm yet, so you should use github as reference

```bash
npm i github:oskolist/apkverifier.js
```

The published package ships pre-built CommonJS + ESM + TypeScript declarations in
`dist/`. Source consumers can also import the `.ts` directly with `tsx`.

## Quick start

```ts
import { verifyApk } from "apkverifier";
import { readFileSync } from "node:fs";

const apk = new Uint8Array(readFileSync("app-release.apk"));

// Just: "is it intact and who signed it?"
const result = await verifyApk(apk);
console.log(result.verified);              // true | false
console.log(result.signerCertSha256);      // ["f7387c306b…", …]  (deduplicated)
console.log(result.schemes.v2.passed);     // true | false | "present"
console.log(result.schemes.v3.passed);     // …

// "is it the *expected* author?"
const known = "f7387c306ba3061f2a4826f60934ddeb1fa447c3d0f4baa8664dbb0943fa1098";
const trusted = await verifyApk(apk, { expectedCertSha256: known });
console.log(trusted.authorVerified);      // true only if that cert signed it

// …or compare against a trusted reference APK:
const ref = new Uint8Array(readFileSync("reference.apk"));
const checked = await verifyApk(apk, { referenceApk: ref });
console.log(checked.authorVerified);      // true if APKs share a signer
```

### Result shape

```ts
interface VerificationResult {
  verified: boolean;            // intact per at least one verified scheme
  schemes: {
    v1: SchemeResult;            // JAR signing  (present/passed + signers + errors)
    v2: SchemeResult;            // APK Signature Scheme v2
    v3: SchemeResult;            // APK Signature Scheme v3 (rotation-aware)
  };
  signerCertSha256: string[];    // deduplicated cert SHA-256 digests of verified signers
  authorVerified: boolean;      // expected signer / reference APK matched
  error?: string;               // fatal error (e.g. malformed ZIP), if any
}

interface SchemeResult {
  present: boolean;              // a signer block for this scheme was found
  passed: boolean;               // every present signer verified
  signers: SignerInfo[];         // per-signer cert + key info
  errors: string[];             // per-scheme diagnostics
}

interface SignerInfo {
  certSha256: string;            // SHA-256 of the X.509 certificate
  certSha1: string;              // SHA-1 of the certificate
  publicKeySha256: string;       // SHA-256 of the SPKI public key
  subject: string | null;        // best-effort CN
  keyAlgorithm: "RSA" | "EC" | "DSA" | "unknown";
  keySize: number;               // RSA modulus bits / EC field size
}
```

### Browser

```html
<script type="module">
  import { verifyApk } from "https://esm.sh/apkverifier";
  const buf = await (await fetch("app.apk")).arrayBuffer();
  const res = await verifyApk(new Uint8Array(buf));
  console.log(res.verified, res.signerCertSha256);
</script>
```

## The three signature schemes

| Scheme | What it signs | Detected by | Notes |
|--------|---------------|-------------|-------|
| **v1** | JAR (MANIFEST.MF + `.SF` + PKCS#7 `.RSA`/`.DSA`/`.EC`) | `META-INF/MANIFEST.MF` exists | Per-entry SHA digests; the legacy scheme. |
| **v2** | A content digest over `apk[0..blockStart]`, `apk[cdOff..eocdOff]`, and a patched EOCD | The `APK Sig Block 42` block (id `0x7109871a`) | Whole-file integrity; catches APK-body tampering. |
| **v3** | Same digest as v2, plus an optional min/max SDK range and a proof-of-rotation attribute | Block id `0xf05368c0` (`PROOF_OF_ROTATION_ATTR_ID = 1000370060`) | Key rotation between signing attempts. |

An APK may carry v1 **and** v2 **and** v3 signatures at once (apksigner signs
with all enabled schemes by default). `verified` is `true` if **any** scheme
verifies. Each scheme's `present`/`passed` is reported independently.

The v2/v3 content-digest formula (1 MiB chunks, `0xa5` per-chunk then `0x5a`
aggregate, SHA-256/512) is implemented to match `com.android.apksig`'s
`ApkSigningBlockUtils.generateApkSigningBlock` and `V2SchemeVerifier` exactly.

## Security & accuracy

- Verification is **bitwise cross-checked** against `apksigner verify --verbose
  --print-certs` in the test suite (`test/verify.test.ts`).
- Only the **digest+signature+key** checks that apksig performs are implemented;
  no extra, weaker heuristics are used.
- The library does **not** validate the signing certificate's trust chain or
  revocation status — it verifies that the bytes match a signature made with the
  *listed* certificate. Trust in a signer is established by the caller via
  `expectedCertSha256` or `referenceApk`.

## Documentation

- **[Quick start: verify an APK](./docs/verify-an-apk.md)**
- **[Verify the signer/author](./docs/verify-the-signer.md)** (certificate pinning & reference APK)
- **[Signature schemes guide](./docs/signature-schemes.md)** (v1/v2/v3, `present` vs `passed`)
- **[API reference](./docs/api-reference.md)** (full typed surface)
- **[Contributor guide](./AGENTS.md)** / **[source architecture](./src/AGENTS.md)**

## Development

This project uses [Nix](https://nixos.org/) to provide a reproducible dev
environment with `apksigner` (the reference oracle), `zip`, `openssl`, and
Node.js 22. See [`AGENTS.md`](./AGENTS.md) for setup and contributor guidance.

```bash
nix develop
npm run typecheck   # tsc --noEmit over src + test
npm run build       # tsc -p .  -> dist/
npm test            # cross-checks library vs apksigner verify
```

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).

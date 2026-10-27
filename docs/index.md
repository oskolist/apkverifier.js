# apkverifier documentation

`apkverifier` is a tiny, zero-runtime-dependency, pure-TypeScript library that
verifies the **author/signer** of an Android `.apk` file. Feed it the bytes of
an APK and it tells you whether the APK is intact (unmodified since it was
signed) and who signed it, across all three APK signature schemes (v1, v2, v3).

It runs in **Node.js ≥ 22** and **modern browsers**, using only the standard
Web platform APIs (`crypto.subtle`, `DecompressionStream('deflate-raw')`).

## Table of contents

- [Quick start](./verify-an-apk.md) — verify an APK and read the result.
- [Check the signer/author](./verify-the-signer.md) — confirm the signer matches
  a known certificate or a trusted reference APK.
- [Signature schemes guide](./signature-schemes.md) — what v1/v2/v3 are and why
  `present`/`passed` matter.
- [API reference](./api-reference.md) — full typed surface.

## Install

```bash
npm i apkverifier
```

The package ships pre-built CommonJS + ESM + TypeScript declarations in `dist/`.
Source consumers can also import the `.ts` directly with `tsx`.

## Import

```ts
// bundlers / ESM
import { verifyApk } from "apkverifier";

// CommonJS
const { verifyApk } = require("apkverifier");
```

## The one thing you need to know

```ts
import { verifyApk } from "apkverifier";

const res = await verifyApk(apkBytes);

res.verified;              // true → the APK is intact (unmodified)
res.signerCertSha256;      // ["f7387c306b…"]  signer cert fingerprint(s)
res.schemes.v2.passed;     // per-scheme detail
res.authorVerified;        // true → signed by *a* signer (no expectation given)
```

That's it. The detailed guides and the API reference explain every option and
result field.

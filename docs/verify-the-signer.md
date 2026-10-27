# How to verify the signer (author) of an APK

Integrity is not identity. `verifyApk(apk)` proves the APK is unchanged since it
was signed — but it does **not** by itself say whether the signer is *your*
author. This guide shows the two ways to confirm the signer is who you expect:
by certificate fingerprint, or by comparison against a trusted reference APK.

In both cases, the result's `authorVerified` field is `true` **only when the APK
is intact *and* one of its verified signers matches your expectation.**

## Option 1 — pin a certificate SHA-256

If you already know the signer's certificate fingerprint (e.g. from a previous
trusted release, or from `apksigner verify --print-certs`), pass it as
`expectedCertSha256`:

```ts
import { verifyApk } from "apkverifier";
import { readFileSync } from "node:fs";

// The SHA-256 fingerprint of the publisher's signing certificate.
const EXPECTED_CERT = "f7387c306ba3061f2a4826f60934ddeb1fa447c3d0f4baa8664dbb0943fa1098";

const apk = new Uint8Array(readFileSync("app-release.apk"));
const result = await verifyApk(apk, { expectedCertSha256: EXPECTED_CERT });

console.log(result.verified);         // was the APK intact at all?
console.log(result.authorVerified);   // true only if intact AND signed by EXPECTED_CERT
```

The comparison is case-insensitive and ignores non-hex characters, so pasting a
uppercase or `ss:`-separated fingerprint also works.

### Behaviour

| Situation | `verified` | `authorVerified` |
|-----------|-----------|------------------|
| Intact AND signed by `EXPECTED_CERT` | `true` | `true` |
| Intact but signed by a *different* cert | `true` | `false` |
| Tampered (content digest mismatch) | `false` | `false` |

This is handy for supply-chain checks: even if the APK is internally consistent,
a different signer means someone re-signed it.

## Option 2 — compare against a trusted reference APK

If you don't have the bare certificate but you *do* have a previously-trusted
APK (e.g. the last release you shipped, or a known-good build from your CI), use
`referenceApk`:

```ts
import { verifyApk } from "apkverifier";
import { readFileSync } from "node:fs";

const candidate = new Uint8Array(readFileSync("app-release.apk"));
const trusted   = new Uint8Array(readFileSync("app-known-good.apk"));

const result = await verifyApk(candidate, { referenceApk: trusted });

console.log(result.verified);         // is the candidate intact?
console.log(result.authorVerified);   // true only if intact AND shares a signer with `trusted`
```

How it works: `apkverifier` verifies the reference APK and computes the set of
*successful* signer-cert fingerprints, then checks that the candidate (once
verified intact) shares at least one of those fingerprints.

### Cross-signing / key rotation

An app may legitimately change signing keys between releases (v3 key rotation).
In that case the reference and candidate may have **different** active signers.
For a strict same-signer check, `referenceApk` is the right tool (it compares the
*full* set of verified signers, including rotated keys); for a looser "is it
from the same publisher" check, compare `signerCertSha256` yourself.

## Reading signer metadata

Every scheme that **passed** is accompanied by `signers: SignerInfo[]`, which
includes `certSha256`, `certSha1`, `publicKeySha256`, `subject`, `keyAlgorithm`
(`"RSA"` | `"EC"` | ...), and `keySize`. The aggregated, deduplicated
`signerCertSha256` at the top level is the convenient "who signed this?" list
for any verified scheme:

```ts
const r = await verifyApk(apk);
for (const fp of r.signerCertSha256) {
  console.log("verified signer cert:", fp);
}
```

`signerCertSha256` only contains signers from schemes that **passed**, so an
empty array means either the APK is unsigned by every scheme, or verification
failed everywhere.

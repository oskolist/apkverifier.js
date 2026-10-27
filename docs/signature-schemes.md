# Signature schemes guide

Android supports three signing schemes. An APK may carry **any combination** of
them, and `apkverifier` reports each one independently as
`schemes.v1` / `schemes.v2` / `schemes.v3` with two flags each.

## `present` vs `passed`

- **`present: true`** — a signer block for that scheme exists in the APK.
- **`passed: true`** — that block was found *and* every signer in it verified
  (signature over the public key, and the content digest over the right APK
  bytes).

So:

| `present` | `passed` | Meaning |
|-----------|---------|---------|
| `true` | `true` | Block present and verified. ✅ |
| `true` | `false` | Block present but verification **failed** (tampering, bad signature, etc.). ❌ |
| `false` | `false` | No block for this scheme (it simply isn't used by this APK). |

`verified` (top-level) is `true` if **any** scheme has `passed: true`.

## The three schemes

### v1 — JAR signing (legacy)

- **What:** the classic Java JAR signature. The APK carries
  `META-INF/MANIFEST.MF`, a `.SF` file, and a PKCS#7 signature block
  (`.RSA`/`.DSA`/`.EC`).
- **Integrity:** per-entry SHA digests in the manifest + a whole-file manifest
  digest in the `.SF`.
- **Why it's weak:** entry-granular digests are vulnerable to certain
  zip-manipulation tricks, and the scheme is slow. apksigner still emits it for
  backward compatibility with very old Android (pre-7.0), but modern Android
  **ignores v1 entirely** if a v2+ block is present.
- **In `apkverifier`:** `schemes.v1.present` is `true` when `META-INF/MANIFEST.MF`
  is in the ZIP central directory. `apksigner`'s v1 `SignerInfo` has **no
  signedAttrs**, so the signature is verified over the raw `.SF` bytes, and the
  signature-algorithm OID is a bare `rsaEncryption`/`id-ecPublicKey` combined
  with a separate digest OID.

### v2 — APK Signature Scheme v2

- **What:** a whole-file signature introduced in Android 7.0 (Nougat).
- **Integrity:** a content digest over three sources — `apk[0..blockStart]`,
  `apk[cdOff..eocdOff]`, and the EOCD (with its central-directory offset patched
  to `blockStart`) — using a 1 MiB chunked `SHA-{h}`: per chunk
  `SHA-{h}([0xa5][u32 LE len][chunk])`, then `SHA-{h}([0x5a][u32 LE count][concat])`.
- **Block:** the `APK Sig Block 42` (16-byte ASCII magic) sitting between the
  ZIP entries and the EOCD. Identified by chunk id `0x7109871a`.
- **Detects:** any modification to the APK body (zip entries, order, alignment).

### v3 — APK Signature Scheme v3

- **What:** v2 with **key rotation** support (Android 9+).
- **Integrity:** same content digest as v2; additionally each signer carries a
  min/max SDK range and (optionally) a `proof-of-rotation` attribute
  (`PROOF_OF_ROTATION_ATTR_ID = 1000370060`) linking successive keys.
- **Block:** chunk id `0xf05368c0`, located in the same `APK Sig Block 42`.
- **Detects:** same as v2, plus it can prove that a new signing key was
  legitimately rotated from a prior one trusted by the platform.

## Typical combinations and what they mean

| Combination | Interpretation |
|-------------|----------------|
| v2 ✅ only | Modern APK, no legacy v1 (common for recent builds). |
| v1 ✅ + v2 ✅ + v3 ✅ | `apksigner` default: signed with all schemes (RSA or EC). |
| v1 ✅, v2 ❌ | v2/v3 broken or stripped → **downgraded security** (v1 is legacy). Reject in production. |
| v2 ✅, v3 ❌ | v3 block absent (not signed with v3). Fine. |
| all passed ❌ | APK was tampered with, the signing block is corrupt, or the signature doesn't verify. Reject. |

## A note on `minSdkVersion` and the oracle

`apkverifier` reports whether each scheme **verifies cryptographically**. It does
not filter v3 signers by `minSdkVersion`/`maxSdkVersion` the way
`apksigner verify --min-sdk-version N` does (a v3 signer whose SDK range excludes
`N` is skipped by the oracle). In practice this only matters for v3, and the
fixtures align so the same schemes pass under both. If you need exact parity with
a specific `apksigner --min-sdk-version` run, account for v3 signer SDK ranges at
the call site when interpreting `schemes.v3`.

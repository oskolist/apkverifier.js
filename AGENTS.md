# AGENTS.md — Contributor & AI-agent Guide

This file explains how to **set up the environment, build, run tests, and
contribute** to `apkverifier`. It is written for humans *and* for AI agents
hacking on this repo. Read it before opening an editor.

## TL;DR

```bash
nix develop /home/user/Git/oskolist/apkverifier.js# -c npm run typecheck
nix develop /home/user/Git/oskolist/apkverifier.js# -c npm run build
nix develop /home/user/Git/oskolist/apkverifier.js# -c npm test
```

All three **must be green** before merging. The canonical shell is
`nix develop /home/user/Git/oskolist/apkverifier.js# -c <cmd>` (see "Tooling"
below — a quoting bug makes `--command "quoted strings"` misbehave, so wrap the
command in `bash -c '...'` for compound commands).

## Environment (Nix)

Dev tools are provided by `flake.nix` → `devShells.default`: `apksigner`,
`nodejs_22`, `zip`, `openssl`. There is **no** `java`/`aapt`/`aapt2` on PATH in
the dev shell — `apksigner` ships its own JVM. The store paths are pinned in
`flake.lock`.

- Node: `/nix/store/...-nodejs-slim-22.23.2/bin/node` (WebCrypto
  `crypto.subtle`, `DecompressionStream('deflate-raw')` all work).
- apksigner wrapper: `/nix/store/lxlv93srwz9cn5c4q8qczsill9ijwk0g-apksigner-35.0.6/bin/apksigner`
  (NOT `java -jar …apk...signer.jar` — there is no `Main-Class`).
- `openssl` at `/home/.nix-profile/bin/openssl`.
- `tz` Note: `apksigner --key` requires a **PKCS#8 DER** key (`*.pk8`); PEM fails.

`node_modules/` is committed-via-setup; `npm install` is already done in the
store Node. `tsc` 5.9.3 and `tsx` are available.

## Scripts (`package.json`)

| Script | What it does |
|--------|--------------|
| `npm run build`        | `tsc -p .` → compiles `src/**/*.ts` to `dist/`. |
| `npm run typecheck`    | `tsc -p tsconfig.test.json --noEmit` over `src` + `test`. |
| `npm test`             | `node --import tsx --test 'test/**/*.test.ts'` — runs the verifier vs `apksigner verify`. |
| `npm run test:watch`   | Same, with `--watch`. |
| `npm run clean`        | `rm -rf dist coverage`. |

## What "done" looks like (success criteria)

- `npm run build`, `npm run typecheck`, `npm test` are **all green** inside
  `nix develop`.
- Library output matches `apksigner verify --min-sdk-version N --max-sdk-version 35 --verbose --print-certs` for:
  - `v1v2v3-rsa.apk` / `v1v2v3-ec.apk` → v1**, **v2**, **v3** all `true`.
  - `v2only-rsa.apk` / `v2only-ec.apk` → v1 absent (`no META-INF/MANIFEST.MF`),
    v2 `true`, v3 absent. Use `--min-sdk-version 24` for v2-only.
  - `tampered-rsa.apk` / `tampered-ec.apk` → `DOES NOT VERIFY` overall;
    library `verified=false`, `v2/v3 passed=false`.
- The reference test suite in `test/verify.test.ts` is the source of truth; do
  **not** weaken its assertions to make a buggy build pass.

## Test fixtures

`test/fixtures.ts` (`ensureFixtures()`) builds everything under `test/_apk/` using
`zip`, `openssl`, and `apksigner`. Generated artifacts (`*.apk`, `*.idsig`,
`*.pk8`, `*.pem`) are **gitignored** (see `.gitignore`) — regenerate by deleting
`test/_apk/` and re-running `npm test`. Do **not** hand-edit the fixtures.

Known-good signer cert SHA-256 digests (regenerated keys; match the oracle):
- RSA: `f7387c306ba3061f2a4826f60934ddeb1fa447c3d0f4baa8664dbb0943fa1098`
- EC:  `879a4224fe3bc1a41ba4fc827458bbb547c524b284de605997edbd6ebd30f3ed`

`supportedMinSdk` values exposed by fixtures: `rsaMinSdk=21`, `ecMinSdk=21`,
`v2onlyMinSdk=24`.

## How the verifier is organized

See [`src/AGENTS.md`](./src/AGENTS.md) for the module map and per-file
responsibilities.

High level: `src/verify.ts` parses the ZIP → locates the APK signing block →
runs v1/v2/v3 in parallel → aggregates. The v2/v3 checks are **already known to
work** for RSA and EC. The **v1** path is the historically-finicky one — see
"v1 gotchas" below.

## Conventions

- **Tabs** for indentation (no spaces) — the repo is tab-indented; match it.
- **No runtime deps** in `src/`. `src/` must **not** import `buffer`,
  `@types/node`, `pako`, or `node-forge`. Tests may use node built-ins. All
  crypto goes through `crypto.subtle` / `crypto.subtle.digest`
  (`src/internal/binary.ts`).
- **No `throw` escapes to callers**: `verifyApk` catches fatal parse errors and
  reports them via `result.error` + the per-scheme `errors` arrays.
- **TypeScript strict** is on. Prefer `Uint8Array` over `Buffer`; avoid BigInt
  where values fit in 53 bits (use `Number(dv.getBigUint64(off, true))` — see
  "u64 gotcha").

## v1 (JAR) gotchas — DO NOT REDO

apksigner's v1 `SignerInfo` is **not** jarsigner's:

1. **No `signedAttrs`**. apksigner emits a `SignerInfo` with `[0] signedAttrs`
   *absent*. Per apksig `V1SchemeVerifier.verifySignerInfoAgainstSigFile`
   (lines 712-788): when signedAttrs are absent, the signature is computed over
   the **raw `.SF` file bytes directly**, and the `messageDigest` attribute
   check is **skipped**. Do not require `messageDigest`.
2. **`signatureAlgorithm` OID is a bare key-algorithm OID**, not a specific sig
   OID:
   - RSA → `1.2.840.113549.1.1.1` (`rsaEncryption`)
   - EC  → `1.2.840.10045.2.1` (`id-ecPublicKey`, RFC 5480)
   
   The digest lives in a *separate* `digestAlgorithm` field. Combine them
   exactly like apksig's `AlgorithmIdentifier.getJcaSignatureAlgorithm`:
   `RSA_ENCRYPTION + SHA-256 → SHA256withRSA` (RSASSA-PKCS1-v1_1_5);
   `EC_PUBLIC_KEY + SHA-256 → SHA256withECDSA`. See `src/internal/alg.ts`
   `oidToSigInfo`.
3. **`SHA-*-Digest-Manifest` lives in the .SF main section**, not in
   `MANIFEST.MF`. Read it via `parseManifest(sfBytes).main`.
4. Every non-META-INF entry referenced by the manifest must exist in the APK,
   its manifest digest must match SHA-x of the entry's *uncompressed* data, and
   the entry must be listed in the `.SF` (signature coverage). `verifyJarEntries`
   enforces all three.

## v2/v3 gotchas — DO NOT REDO

- The magic is the **16-byte ASCII** `"APK Sig Block 42"` at `cdOff - 16`
  (NOT the 8-byte `0x0a85ddee0d99bff0`).
- `size2 = u64 @ (cdOff - 24)` where `magicOff = cdOff - 16`; `size1 == size2`;
  `blockStart = cdOff - 8 - size2` and `blockStart % 4096 == 0`.
- Block layout (apksig `generateApkSigningBlock`, lines 846-902):
  `[u64 size1][chunks…][u64 size2][16-byte magic]`. `size1`/`size2` EXCLUDE the
  8-byte size field (`sizeField = resultSize - 8`).
- Each chunk: `[u64 sz = 4 + valueLen][u32 id][value]`, span `8 + sz`,
  `valueLen = sz - 4`. **Wrong**: naive `[u32 id][u32 len]` header, or treating
  `sz` as including the size field (off-by-8). Use
  `iterateChunks(data, blockStart + 8, magicOff - 8)`.
- v2 chunk id `0x7109871a`; v3 chunk id `0xf05368c0`.
  `PROOF_OF_ROTATION_ATTR_ID = 1000370060`.
- Content digest (1 MiB chunks): `SHA-{h}([0xa5][u32 LE chunkLen][chunk])` per
  chunk, then `SHA-{h}([0x5a][u32 LE count][concat of chunk digests])`. Three
  sources: `apk[0..blockStart]`, `apk[cdOff..eocdOff]`, and the EOCD (22 + comment)
  with its cd-offset `u32 @16` patched to `blockStart`.
- v2 signer/signedData layout (apksig `V2SchemeVerifier.parseSigner`, lines
  244-285): `chunkData = [u32 lenSigners][signersSeq]`; each signer =
  `[u32 len][ [len][signedDataBytes] [len][sigs] [len][pubkey(SPKI)] ]` (+ min/max
  SDK after signedData for v3); `signedDataBytes = [u32 len][digests][u32 len][certs][u32 len][addlAttrs][u32 0 trailing]` (v2 only). Use `lpEntries`
  for the digest/sig/cert sequence readers, NOT `lpSeq`.

### Node vs. browser ECDSA sig-encoding gotcha

Node 22 `crypto.subtle` ECDSA `sign()` returns **raw `r‖s`** (64 bytes for
P-256) and `verify()` **rejects DER**. Browsers follow the W3C spec and expect
DER. `src/internal/alg.ts` `verifySig` tries DER first, then converts
**DER → raw `r‖s`** via `derToRawEcdsa` (padding each field to
P-256→32 / P-384→48 / P-521→66 bytes). Keep both paths. RSA sig alg oid is
`rsaEncryption` → RSASSA-PKCS1-v1_5.

## u64 gotcha

`readU64LE` returns a JS **number** (values here fit in 53 bits — e.g. 4088).
Do **not** use `BigInt('0x'+hex)`; use `Number(dv.getBigUint64(off, true))`.

## Where to find things (quick index)

- Public API: `src/index.ts`, `src/verify.ts`, `src/types.ts`, `src/errors.ts`.
- ZIP/EOCD/CD/LFH: `src/internal/zip.ts`.
- APK signing block (magic, sizes, chunks): `src/internal/apk-signature-block.ts`.
- Content digest (0xa5/0x5a): `src/internal/content-digest.ts`.
- Signer parsing + verification (v2/v3): `src/internal/signer.ts`.
- v1/v2/v3 entry points: `src/internal/v1.ts`, `v2.ts`, `v3.ts`.
- ASN.1/DER (PKCS#7, X.509, SPKI): `src/internal/asn1.ts`.
- ASN.1 OID → WebCrypto algorithm + signature verify: `src/internal/alg.ts`.
- Certificate info (SHA-256/SHA-1, SPKI, subject, key size): `src/internal/cert-info.ts`.
- Manifest (MANIFEST.MF / .SF) parsing: `src/internal/manifest.ts`.
- Low-level bytes (LE readers, hex, sha256/512/1, inflateRaw): `src/internal/binary.ts`.

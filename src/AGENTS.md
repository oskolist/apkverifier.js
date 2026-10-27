# src/AGENTS.md — Source Architecture

`apkverifier` is structured as a small orchestrator (`src/verify.ts`) over a set
of focused, dependency-free internal modules under `src/internal/`. Everything
in `src/` targets the Web platform (Node 22 + modern browsers) and must **not**
import `buffer`, `@types/node`, `pako`, or `node-forge` — all crypto goes through
the standard WebCrypto API (`crypto.subtle`).

## Module map

### Public surface (`src/`)

| File | Responsibility |
|------|----------------|
| `src/index.ts` | Single export re-export: `verifyApk`, plus the types. |
| `src/verify.ts` | `verifyApk(apk, opts)` orchestrator: parses the ZIP, locates the APK signing block, runs v1/v2/v3 **in parallel**, deduplicates signer cert SHA-256s across verified schemes, and computes `authorVerified` from `expectedCertSha256` / `referenceApk`. Fatal errors are caught and surfaced via `result.error` + per-scheme `errors`. |
| `src/types.ts` | `VerificationResult`, `SchemeResult`, `SignerInfo`, `VerifyApkOptions`, `KeyAlgorithm`. |
| `src/errors.ts` | `ApkVerifyError` + `VERIFY_ERROR` codes (`BAD_ZIP`, `BAD_SIGNING_BLOCK`, `NO_MANIFEST`, `PARSE_ERROR`). |

### Internal (`src/internal/`)

| File | Responsibility | Key functions / constants |
|------|----------------|---------------------------|
| `binary.ts` | LE readers, hex, sha256/384/512/1, `concat`, `inflateRaw` (WebCrypto + `DecompressionStream('deflate-raw')`). No Node-specific deps. | `readU32LE`, `readU64LE` (→ JS number), `hex`, `sha256`, `concat`, `inflateRaw`. |
| `zip.ts` | ZIP structure: EOCD search (scan-back, `u16` commentLen), central directory, local-file entries. | `getZipSections`, `findEocd`, `readEntry` (methods 0/8; `8` → `inflateRaw`). |
| `apk-signature-block.ts` | APK Signature Scheme v2/v3 block framing. | `findSigningBlock`, `iterateChunks`, `findChunk`, `V2_BLOCK_ID` (`0x7109871a`), `V3_BLOCK_ID` (`0xf05368c0`). |
| `content-digest.ts` | v2/v3 whole-file content digest (the `0xa5`/`0x5a` formula). | `computeContentDigest`, `eocdTotalLen`, `EOD_CODING_CHUNK` (1 MiB). |
| `signer.ts` | Parse & verify v2/v3 signer records (digest + signature + public key). | `verifyScheme(apk, chunk, isV3, …)`, `parseSignerBlock`, `verifySigner`. Uses `lpEntries` (not `lpSeq`) for the digest/sig/cert sequence readers. |
| `v1.ts` | JAR (PKCS#7) verification. | `verifyV1(apk, entries)`. |
| `v2.ts` | Thin wrapper: `verifyScheme(apk, data, blockStart, cdOff, eocdOff, false)`. | |
| `v3.ts` | Thin wrapper: `verifyScheme(apk, data, blockStart, cdOff, eocdOff, true)` + rotation/proof-of-rotation parsing. | |
| `asn1.ts` | Minimal DER reader for PKCS#7 / X.509 / SPKI. | `readTLV`, `children`, `decodeOid`, `decodeInteger`, `parsePkcs7`, `parseX509Cert`, `OID`, `OID_TO_HASH`, `oidToHash`. |
| `alg.ts` | OID → WebCrypto algorithm mapping + signature verification. | `sigAlgInfo` (v2/v3 int IDs → `SigAlgorithmInfo`), `oidToSigInfo` (v1 OIDs → info, handles bare `rsaEncryption`/`id-ecPublicKey` + digest), `ecNamedCurve`/`ecCurveOid`, `importSpki`, `verifySig` (DER→raw r‖s fallback for EC), `derToRawEcdsa`, `digestHashForAlgId`. |
| `cert-info.ts` | Derive signer metadata (cert SHA-256/1, SPKI, subject, key alg/size) from an X.509 cert. | `certInfo`, `spkiInfo`. |
| `manifest.ts` | Parse manifest-format files (MANIFEST.MF and .SF): main section + named per-entry sections + attributes. | `parseManifest`, `b64toBytes`. |

## Request flow (`verifyApk`)

```
verifyApk(bytes):
  1. getZipSections(bytes)            →  cdOff, eocdOff, entries   (zip.ts)
       on failure → { verified:false, error:"bad ZIP…" }
  2. findSigningBlock(bytes, cdOff)    →  { blockStart, chunks }?   (apk-signature-block.ts)
       on bad framing → error reported; v2/v3 reported present:false
  3. PARALLEL:
       v1P = verifyV1(bytes, entries)                 // src/internal/v1.ts
       v2P = findChunk(V2) ? verifyScheme(...,false)  // signer.ts
       v3P = findChunk(V3) ? verifyScheme(...,true)
  4. dedupe cert SHA-256 across verified signers (v1.signers + v2.signers + v3.signers)
  5. verified = v1.passed || v2.passed || v3.passed
  6. authorVerified:
       default verified
       expectedCertSha256 → verified && certs ∩ expected
       referenceApk        → verified && certs ∩ (await verifyApk(ref).certSha256)
  7. aggregate v1/v2/v3 errors into result.error
```

## v2/v3 content digest (the heart of tamper detection)

`computeContentDigest` (3 sources) matches apksig
`ApkSigningBlockUtils`:
1. `apk[0 .. blockStart]`
2. `apk[cdOff .. eocdOff]`
3. the EOCD record (22 bytes + comment) with its **cd-offset `u32 @16` patched to
   `blockStart`** (so the digest is stable regardless of where the signer
   relocated the central directory).

Each source is split into 1 MiB chunks. Per chunk:
`SHA-{h}([0xa5][u32 LE len][chunk bytes])`. Concatenate the chunk digests, then:
`SHA-{h}([0x5a][u32 LE count][concat])`. `h` is SHA-256 (alg id 259) normally,
SHA-512 (260) for the SHA-512 digest entries. A tampered APK changes a byte in a
chunk → digest mismatch → `v2/v3 passed=false`.

## What already works (do not churn)

- v2 and v3 verification **pass for RSA and EC** (confirmed against
  `f7387c30…` / `879a4224…`). The signing-block locator, chunk framing, signer
  parsing, content-digest and ECDSA DER→raw conversion are all correct.
- v1 now passes for `v1v2v3-rsa`/`v1v2v3-ec` (sig over the `.SF` bytes when
  signedAttrs are absent; manifest digest read from the `.SF` main section;
  sig-alg OID combined with digest OID).

## What NOT to touch

- Do **not** search for the 8-byte magic `0x0a85ddee0d99bff0` — it does not
  appear in these APKs; the magic is the 16-byte ASCII `"APK Sig Block 42"`.
- Do **not** re-implement `inflateRaw` with `pako`/`node-zlib`; the
  `DecompressionStream('deflate-raw')` path in `binary.ts` is correct for
  both Node 22 and browsers.
- Do **not** weaken the test oracle assertions in `test/verify.test.ts`.

## Testing

`npm test` runs `test/verify.test.ts`, which:
1. `ensureFixtures()` (→ `test/fixtures.ts`) builds reference APKs with `zip` +
   `openssl` + `apksigner`, and exposes `rsaApk`, `ecApk`, `v2onlyRsaApk`,
   `v2onlyEcApk`, `tamperedRsaApk`, `tamperedEcApk`, cert SHA-256s, and min-sdk
   hints.
2. For each APK, compares the library's `verifyApk` output against
   `apksigner verify --min-sdk-version N --max-sdk-version 35 --verbose --print-certs`
   (the oracle), including the tampered-rejection case.

Regenerate fixtures with `rm -rf test/_apk && npm test`.

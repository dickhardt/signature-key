# Signature-Key test vectors

Test vectors for HTTP Signature Keys (`draft-hardt-httpbis-signature-key`),
in the shape asked for in issue #25 and modeled on RFC 9421 Appendix B.
Each vector gives the full request, the RFC 9421 signature base verbatim,
the key material including private keys, the expected `Signature-Input`,
`Signature` and `Signature-Key` header fields, the documents a verifier
resolves for the discovery schemes, and the result the draft fixes.

## Files

| Path | Content |
| --- | --- |
| `signature-key-vectors.json` | the vectors, machine-readable. It is authoritative and needs no network access |
| `APPENDIX.md` | the same vectors for reading, long lines folded per RFC 8792 |
| `served/<host>/<path>` | the default documents from the file's `documents` member, byte for byte, for an implementer who serves them over HTTPS |
| `served/by-vector/<vector id>/<host>/<path>` | the documents one vector serves in place of the default at the same URL |

The x509 trust anchor and CRL are in the file's `x509` member, not under
`served/`. The JSON file's `description` names `vectors/signature-key/README.md`,
its path in the repository that generated it (see below).

## Contents

67 vectors: 41 expect the request to verify, 24 expect a refusal, and 2
accept either a verification or a refusal with `unsupported_algorithm`. Of
the 41, 8 are must-accept boundary vectors (see below).

| Scheme | verify | reject | verify or reject |
| --- | --- | --- | --- |
| hwk | 12 | 11 | |
| jwt | 7 | 4 | |
| jwks_uri | 4 | 4 | 1 |
| jkt-jwt | 6 | 1 | |
| jwks | 3 | 1 | 1 |
| self-jwt | 5 | 1 | |
| x509 | 3 | | |
| cached | | 1 | |
| an unregistered scheme token | | 1 | |
| hwk and jwks on one request (two signatures) | 1 | | |

| Algorithm | verify | reject | verify or reject |
| --- | --- | --- | --- |
| Ed25519 | 22 | 22 | |
| ES256 | 14 | | |
| ES384 | 2 | 1 | |
| PS256 | 2 | | |
| RS256 | 1 | | |
| ML-DSA-44 | | | 2 |
| HS256 | | 1 | |

The file holds 15 keys, each with its private material, 7 default
documents, 6 per-vector documents, and the x509 chains, trust anchor and
CRL.

## Categories

Every vector carries the category issue #25 defines.

| Category | Meaning | What to check |
| --- | --- | --- |
| 1 | key handling | the key selection or refusal |
| 2 | verify-only | the signature verifies. ECDSA and RSA-PSS signatures are randomized: never recompute and compare them (RFC 9421 Section 3.3.4) |
| 3 | reproduce-the-bytes | Ed25519 and RS256 are deterministic: signing `signature_base` with the private key gives exactly `signed.Signature`. So is ML-DSA-44 in the FIPS 204 deterministic variant, which the ML-DSA-44 vectors use |

The file has 2 vectors in category 1, 19 in category 2 and 46 in category 3.

## How to evaluate a vector

1. Build the received request: `request` with the `signed` header fields
   added.
2. Evaluate it as if the current time were `now`, with the `verifier`
   configuration: the Resource at `verifier.resource`, label `sig`, a
   60-second window, the listed schemes and algorithms. A vector with a
   `signatures` member replaces label `sig` with every label it lists, and
   each label is verified over its own base.
3. Resolve keys only from the documents: the file's `documents`, with the
   vector's own `documents` replacing any at the same URL. x509 chains are
   documents too; the trust anchors and CRLs are in `x509`.
4. Compare the result with `expect`.

| `expect.outcome` | Passes when |
| --- | --- |
| `verify` | the request verifies; for a vector with `signatures`, every listed label verifies |
| `reject` | the request is refused, with `Signature-Error` `error` equal to `expect.error`. An absent `error` means the drafts fix no code, so any `Signature-Error` passes |
| `verify-or-reject` | the request verifies, or is refused with `expect.error`. It is used for the two ML-DSA-44 requests: a verifier that does not implement ML-DSA-44 must decline with `unsupported_algorithm` |

`expect.required_input_includes` names components a refusal's
`required_input` should list. It is RECOMMENDED, so a vector passes
without it.

A vector with an `optional` member may be skipped for its category check.
The member says why, and what is still graded. Only
`jwks-ml-dsa-44-deterministic` has one.

## Members

Top level:

| Member | Content |
| --- | --- |
| `drafts` | the pinned drafts: name, commit, SHA-256 of the file, URL |
| `generated` | the library revisions that signed and checked this file, and the harness |
| `verifier` | the verifier configuration every expectation assumes |
| `keys` | every key: `id`, `alg`, `public_jwk`, `private_jwk`, the Ed25519 or ML-DSA-44 `seed_hex` or the EC or RSA `pkcs8_base64`, and the `derivation` that reproduces it |
| `documents` | the default documents a verifier can fetch: `url`, `content_type`, `body` |
| `x509` | the x509 trust anchors and CRLs, DER, base64 |
| `vectors` | the vectors |

Each vector:

| Member | Content |
| --- | --- |
| `id`, `title` | name. An id ending in `.rust` or `.go` is one implementation's signature, where both signed and the randomized signatures differ |
| `category` | 1, 2 or 3, as above |
| `scheme`, `alg` | the selected member's scheme and the request signature algorithm. A vector with `signatures` has no `scheme` |
| `now` | the verification time, Unix seconds |
| `request` | the request before signing: `method`, `url`, `headers`, `body` |
| `signed` | the header fields signing added: `Signature-Input`, `Signature`, `Signature-Key` and, with content, `Content-Digest` |
| `signature_base` | the RFC 9421 signature base for label `sig`, verbatim, with `signature_base_sha256` and `signature_base_length` |
| `signature_verifies` | whether `Signature` verifies over the base under the key the member conveys, when that key is well formed. It separates a canonicalization fault from a cryptographic one |
| `signing_key` | the `keys` id that produced the signature. Absent with `signatures` |
| `signatures` | only on a request with more than one signature: per label, its `scheme`, `alg`, `signing_key`, `signature_base` with SHA-256 and length, `signature_verifies` and `resolves`. The top-level `signature_base` is then absent |
| `assertion` | for jwt, jkt-jwt and self-jwt: the compact JWT, its decoded header and payload, and the key that signed it |
| `documents` | documents that replace the defaults for this vector |
| `resolves` | the document URLs key resolution reads |
| `expect` | `outcome`, `error` and `basis`, the draft lines the expectation rests on |
| `optional` | on a vector whose category check an implementation may skip: why, and what is still graded |
| `provenance` | `signed_by` (`aauth-rust`, `aauth-go` or `harness`), `reproduced_by` (implementations that produced the same bytes), `mutation` and a `note` |

## Multiple signatures

`multi-hwk-jwks` carries two Ed25519 signatures on one GET request: `sig1`
under hwk and `sig2` under jwks. The `Signature-Key` field holds both
members before either signature is made, and both signatures cover
`signature-key` (draft lines 191 and 199).

Which labels a verifier checks is application context (draft lines 173 and
181). For this vector the verifier is configured to verify `sig1` and
`sig2` in place of `sig`, as its title and `expect.basis` state, and the
vector passes only when both verify. A verifier that checks only `sig`
finds no signature under that label in this request.

Each label's base is in `signatures`. RFC 9421 leaves the label out of the
signature base, so the two bases are the same bytes; each signature
verifies only under the key its own member conveys.

## Boundary vectors

Refusals alone cannot catch a verifier that over-blocks: one that rejects
everything passes every negative vector. The eight `accept-*` vectors sit
one step from a MUST-reject rule and must verify. Each title starts
"boundary, must verify", and each `expect.basis` cites the line that puts
the boundary there.

| Vector | One step from |
| --- | --- |
| `accept-created-window-ahead` | `created` 60 seconds ahead. 61 is `clock_skew` (protocol line 2246, draft line 1106) |
| `accept-created-window-behind` | `created` 60 seconds old. 61 is `invalid_signature` (protocol line 2246, draft line 1114) |
| `accept-jwt-exp-next-second`, `accept-jkt-jwt-exp-next-second`, `accept-self-jwt-exp-next-second` | `exp` one second after `now`. At `now` the assertion has expired (draft line 1086, protocol line 2317) |
| `accept-jwt-nbf-now`, `accept-jkt-jwt-nbf-now`, `accept-self-jwt-nbf-now` | `nbf` equal to `now`. One second later it is not yet valid (RFC 7519 Section 4.1.5, which the drafts apply to every JWT: protocol line 2313, draft lines 1194-1198) |

There is no `iat` boundary vector. A verifier is not required to bound
`iat` (draft line 1114), so no `iat` must be refused.

## ML-DSA-44

Two vectors carry an ML-DSA-44 request signature. Both are
`verify-or-reject` with `unsupported_algorithm`: a verifier that implements
ML-DSA-44 verifies them, and one that does not must decline with that code
(draft line 233).

- `jwks-uri-ml-dsa-only` (category 1) resolves a jwks_uri whose only key is
  ML-DSA-44.
- `jwks-ml-dsa-44-deterministic` (category 3) resolves a jwks key and is
  signed with the FIPS 204 deterministic variant (rnd all zeros, empty
  context), the only form whose bytes reproduce. It is `optional`. Most
  libraries do not expose the deterministic variant, so a signer without it
  may skip reproducing the bytes. Verification is graded the same either
  way.

## Fixed values

- `now` is 1800000000 for every vector, and `created` equals it except in
  the four window vectors.
- Agent tokens (jwt) and jkt-jwt assertions are issued 300 seconds before
  `now` and expire 3000 seconds after it. self-jwt assertions are issued 30
  seconds before and expire 300 seconds after. The vectors for an expired
  token, a missing `exp`, an `exp` one second after `now` and an `nbf` equal
  to `now` differ, as their titles say.
- The names are example domains: `resource.example`, `agent-provider.example`,
  `signer.example`, `keys.example` and `certs.example`.
- The jwt vectors carry an AAuth agent token (`typ` `aa-agent+jwt`), so the
  jwt scheme's deployment `typ` policy is AAuth's. The self-jwt `typ` is
  `vector-self+jwt`.
- Ed25519 and ML-DSA-44 seeds are SHA-256 of
  `aauth-conformance signature-key vectors <key id>`. P-256 and P-384
  private scalars are SHA-256 and SHA-384 of that string. The RSA keys are
  fixed test keys. Every key is a published test key.
- The x509 root and both end-entity certificates are signed with the
  Ed25519 root key, so their DER is reproducible.

## Pinned drafts

The expectations come from the drafts, not from either implementation.

| Draft | Commit | SHA-256 of the file |
| --- | --- | --- |
| `draft-hardt-httpbis-signature-key.md` in this repository | `69f5ba2647be848feed043fb6d8b0790e43cd0b6` | `b2b43db67a1aa5249d1166589834d44f81e97ea2e6375a07b475115efa196b7d` |
| `draft-hardt-oauth-aauth-protocol.md` in dickhardt/AAuth | `70d67375deb0bb002af7da0711fc58f6e8926e7e` | `99ef2430c7babec7ea9cb2e9af40e3c3c57d18bce5a6e8501e9748063cfd9ab0` |

The signature-key commit is this repository's `main` when the vectors were
made. Where the signature-key draft leaves an error code open, the AAuth
protocol's Verification (Server) steps fix it. Every `expect.basis` cites
line numbers in these files.

## How the vectors were produced and checked

The vectors were generated and cross-checked with two implementations, in
two languages:

| Implementation | Language | Revision |
| --- | --- | --- |
| [aauth-rust](https://gitlab.com/sidecat-dev/aauth-rust) | Rust | `ed4671b6a6b03993480a1b7fa8ca156c6ae607bd` (v0.1.0-alpha.28) |
| [aauth-go](https://gitlab.com/sidecat-dev/aauth-go) | Go | `ad34a9ad148cd2dd0f96b77e387c4fd22a3ca535` |

The generator is `cmd/sigkey-vectors` in
[aauth-conformance](https://gitlab.com/sidecat-dev/aauth-conformance).

1. Each implementation signs every positive case with its own signer
   (aauth-rust `sign_requests`, aauth-go `SignRequests`) at the fixed
   `created`.
2. A harness that uses only the Go standard library, and neither
   implementation, checks each signed request. It rebuilds the signature
   base from the received request and verifies the signature. It also
   compares `Signature-Input`, `Signature-Key` and `Content-Digest` with
   what the drafts give.
3. A deterministic case is published once when both implementations
   produce the same bytes, and `reproduced_by` names the second. A
   randomized case is published once per implementation.
4. A negative vector is one implementation's signed request with the
   defect applied, such as a flipped signature bit, a renamed label, an
   expired assertion or a changed document. Where a conforming signer
   refuses to produce the defect, the harness signs it, and
   `provenance.note` says why.
5. Neither implementation signs with ML-DSA-44, so the harness signs both
   ML-DSA-44 vectors, with Go's `crypto/mldsa` in the deterministic
   variant. The harness signed 10 vectors in all.
6. Every vector is then run through each implementation's verifier, with
   the `verifier` configuration (for `multi-hwk-jwks`, labels `sig1` and
   `sig2`). For this file, all 67 vectors gave the `expect` result in both
   implementations.
7. `sigkey-vectors -check` signed every case again, with each
   implementation that signs it, and found no difference from the file
   apart from randomized signatures.

A few cases have one signer. `hwk-ed25519-nonce` is signed by aauth-go
only, because aauth-rust's signer takes no `nonce` parameter, and
aauth-rust verifies it. `reject-self-jwt-cnf` and
`reject-jkt-jwt-iss-mismatch` are signed by aauth-go only, because
aauth-rust's signer refuses those assertions. `reject-cached-unknown-cid` is
signed by aauth-rust only, because aauth-go presents only cache identifiers
a verifier issued.

`signature-key-vectors.json` is byte-identical to
`vectors/signature-key/signature-key-vectors.json` in aauth-conformance at
commit `f415f2f8e18bebb2b4b6928d96c80d999244e72a`, SHA-256
`017013cc02433249f9e686df4743afd2cdb21025e41da4bbf339e0031dd616a4`.

## Codes a static file cannot reach

The draft registers 14 `Signature-Error` codes, and the vectors expect 12
of them. No vector expects these two:

- `invalid_request`: the request lacks something the application requires,
  unrelated to the signature (draft line 1038). The draft does not say what
  an application requires, so no file can fix a request that lacks it.
- `revoked_jwt`: the verifier holds notice from the issuer that a valid,
  unexpired JWT was withdrawn (line 1094), and how it learns of that is out
  of scope (line 1102). A file can carry the JWT but not the notice.

Three codes are reached only in part:

- `clock_skew` is expected for a `created` ahead of the window, not for an
  `iat`, because bounding `iat` is optional for a verifier (line 1114).
- `cache_miss` is expected for an identifier the verifier never issued. A
  cache hit needs an identifier that verifier issued earlier.
- `invalid_key` is expected for a key that disagrees with its `alg`, not
  for one that fails the verifier's trust requirements (line 1046), which
  are its own policy.

## Not covered

- Live endpoints: every document is in the file.
- A request carrying a second label while the verifier verifies only `sig`:
  which labels a verifier checks is application context (draft lines 173
  and 181), so the draft fixes no result for it.

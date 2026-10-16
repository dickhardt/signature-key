# Signature-Key test vectors

Test vectors for each `Signature-Key` scheme, for issue #25.

Source of truth is the draft text, not an implementation. Every base below was
rebuilt from the draft and then checked, rather than emitted by a signer and
trusted.

## Files

| file | what it is |
| --- | --- |
| `signature-key-vectors.json` | the vectors, machine readable, base unfolded |
| `gen_vectors.py` | the generator, which rebuilds the JSON byte for byte |
| `requirements.txt` | `cryptography` and `dilithium-py` |
| `served/` | 12 discovery documents, served at the hosts the vectors name |

## What is in it

31 vectors, 11 positive and 20 negative, across hwk for OKP and EC, jkt-jwt,
jwks_uri, jwks, jwt, jwt with cache requested, self-jwt, a multi-signature case
and ML-DSA-44. Of the 20 negatives, 17 are must-reject and 3 are MUST ACCEPT
controls, which are there so a verifier that rejects everything cannot pass.

All 31 publish the RFC 9421 signature base verbatim with its byte length and
SHA-256, so an implementation that fails one can tell a canonicalization fault
from a crypto one. `created` is 1791275958 throughout and the covered
components are `@method @authority @path signature-key`. Keys come from fixed
seeds, so rerunning the generator reproduces every value.

10 of the 14 `Signature-Error` codes are exercised: clock_skew, expired_jwt,
invalid_input, invalid_jwt, invalid_key, issuer_mismatch, issuer_missing,
unknown_key, unsupported_algorithm, unsupported_scheme. The other four are out
of reach of a static file: `invalid_signature` is covered by the existing
`http-signature.json` fixtures, `invalid_request` is for malformations
unrelated to this header, `revoked_jwt` lives entirely in verifier state, and
`cache_miss` belongs to the `cached` scheme.

Each negative is a complete signed request carrying exactly one fault, so an
end-to-end verifier reaches the rule under test instead of stopping at
`invalid_signature`. Because the key the faulty header names is usually the
fault itself, each one also publishes `signing_key`, the key that actually made
the signature. `field_notes` in the JSON says what each field means.

## Running it

```
pip install -r requirements.txt
python3 gen_vectors.py
```

The generator rewrites the JSON and the `served/` tree, then verifies both
directions against the base the file publishes: 15 signatures a signer is
expected to produce, and 18 a verifier is handed. It exits non-zero if any of
them fails, if two vectors claim one discovery path with different documents,
or if the multi-signature labels collapse onto one key.

## Two open points

Two must-reject vectors carry no signature and say so in `unsigned_reason`.
`hwk-symmetric-forbidden` declares `kty` of `oct` and the scheme defines no
symmetric mode, so there is no signing procedure for the key that member names.
`unknown-scheme-selected` is unknown by construction. Signing either under some
unrelated key would add a second fault.

Seven negatives expect error codes the draft does not yet name. Those follow
the draft once the codes are pinned, along with the RFC 8792 folded appendix.

The set is CC0.

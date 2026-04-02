%%%
title = "HTTP Signature-Key Header"
abbrev = "Signature-Key"
ipr = "trust200902"
area = "Applications and Real-Time"
workgroup = "HTTP"
keyword = ["http", "signature", "authentication", "jwk", "jwt"]

[seriesInfo]
status = "standard"
name = "Internet-Draft"
value = "draft-hardt-httpbis-signature-key-latest"
stream = "IETF"

date = 2026-03-26T00:00:00Z

[[author]]
initials = "D."
surname = "Hardt"
fullname = "Dick Hardt"
organization = "Hellō"
  [author.address]
  email = "dick.hardt@gmail.com"

[[author]]
initials = "T."
surname = "Meunier"
fullname = "Thibault Meunier"
organization = "Cloudflare"
  [author.address]
  email = "ot-ietf@thibault.uk"

%%%

.# Abstract

This document defines the Signature-Key HTTP header field for distributing public keys used to verify HTTP Message Signatures as defined in RFC 9421. Four initial key distribution schemes are defined: pseudonymous inline keys (hwk), identified signers with JWKS URI discovery (jwks_uri), X.509 certificate chains (x509), and JWT-based delegation (jwt). These schemes enable flexible trust models ranging from privacy-preserving pseudonymous verification to PKI-based identity chains and horizontally-scalable delegated authentication.

.# Discussion Venues

*Note: This section is to be removed before publishing as an RFC.*

Source for this draft and an issue tracker can be found at https://github.com/dickhardt/signature-key.

{mainmatter}

# Introduction

HTTP Message Signatures [@!RFC9421] provides a powerful mechanism for creating and verifying digital signatures over HTTP messages. To verify a signature, the verifier needs the signer's public key. While RFC 9421 defines signature creation and verification procedures, it intentionally leaves key distribution to application protocols, recognizing that different deployments have different trust requirements.

This document defines the Signature-Key HTTP header field to standardize key distribution for HTTP Message Signatures. The header enables signers to provide their public key or a reference to it directly in the HTTP message, allowing verifiers to obtain keying material without prior coordination.

The header supports four schemes, each designed for different trust models and operational requirements:

1. **Header Web Key (hwk)** - Self-contained public keys for pseudonymous verification
2. **JWKS URI (jwks_uri)** - Identified signers with key discovery via metadata
3. **X.509 (x509)** - Certificate-based verification with PKI trust chains
4. **JWT (jwt)** - Delegated keys embedded in signed JWTs for horizontal scale
5. **JKT JWT (jkt-jwt)** - Self-issued key delegation via JWK Thumbprint JWTs ("jacket jot")

Additional schemes may be defined through the IANA registry established by this document.

The Signature-Key header works in conjunction with the Signature-Input and Signature headers defined in RFC 9421, using matching labels to correlate signature metadata with keying material.

# The Signature-Key Header Field

The Signature-Key header field provides the public key or key reference needed to verify an HTTP Message Signature. The header is a Structured Field Dictionary [@!RFC8941] keyed by signature label, where each member describes how to obtain the verification key for the corresponding signature.

**Format:**

```
Signature-Key: <label>=<scheme>;<parameters>...
```

Where:
- `<label>` (dictionary key) matches the label in Signature-Input and Signature headers
- `<scheme>` (token) identifies the key distribution scheme
- `<parameters>` are semicolon-separated key-value pairs whose values are structured field strings or byte sequences, varying by scheme

Multiple keys are comma-separated per the dictionary format. See [@!RFC8941] for definitions of dictionary, token, string, and byte sequence.

**Example:**

```
Signature-Input: sig=("@method" "@authority" "@path" "signature-key"); created=1732210000
Signature: sig=:MEQCIA5...
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="JrQLj..."
```

**Label Correlation:**

Labels are correlated by equality of label names across Signature-Input, Signature, and Signature-Key. Signature-Key is a dictionary keyed by label; Signature-Input and Signature are the sources of what signatures are present; Signature-Key provides keying material for those labels.

Verifiers MUST:

1. Parse Signature-Input and Signature per RFC 9421 and obtain the set of signature labels present. The verifier determines which labels it is attempting to verify based on application context and RFC 9421 processing.

2. Parse Signature-Key as a Structured Fields Dictionary

3. For each label being verified, select the Signature-Key dictionary member with the same name

4. If the Signature-Key header is present and the verifier is attempting to verify a label using it, but the corresponding dictionary member is missing, verification for that signature MUST fail

> **Note:** A verifier might choose to verify only a subset of labels present (e.g., the application-required signature); labels not verified can be ignored.

Signatures whose keys are distributed through mechanisms outside this specification (e.g., pre-configured keys, out-of-band key exchange) are out of scope. A Signature-Key header is not required for such signatures, and verifiers MAY use application-specific means to obtain the verification key.

## Label Consistency

If a label appears in Signature or Signature-Input, and the verifier attempts to verify it using Signature-Key, the corresponding member MUST exist in Signature-Key. If Signature-Key contains members for labels not being verified, verifiers MAY ignore them.

## Multiple Signatures

The dictionary format supports multiple signatures per message. Each signature has its own dictionary member keyed by its unique label:

```
Signature-Input: sig1=(... "signature-key"), sig2=(... "signature-key")
Signature: sig1=:...:, sig2=:...:
Signature-Key: sig1=jwt;jwt="eyJ...", sig2=jwks_uri;id="https://example.com";dwk="meta";kid="k1"
```

Most deployments SHOULD use a single signature. When multiple signatures are required, the complete Signature-Key header (containing all keys) MUST be populated before any signature is created, and each signature MUST cover `signature-key`. This ensures all signatures protect the integrity of all key material. See [Signature-Key Integrity](#signature-key-integrity) in Security Considerations. Alternative key distribution mechanisms outside this specification may be used for scenarios requiring independent signature addition.

## Header Web Key (hwk)

The hwk scheme provides a self-contained public key inline in the header, enabling pseudonymous verification without key discovery. The parameter names and values correspond directly to the JWK parameters defined in [@!RFC7517].

**Parameters by key type:**

OKP (Octet Key Pair):

- `kty` (REQUIRED, String) - "OKP"

- `crv` (REQUIRED, String) - Curve name (e.g., "Ed25519")

- `x` (REQUIRED, String) - Public key value

```
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="JrQLj5P..."
```

EC (Elliptic Curve):

- `kty` (REQUIRED, String) - "EC"

- `crv` (REQUIRED, String) - Curve name (e.g., "P-256", "P-384")

- `x` (REQUIRED, String) - X coordinate

- `y` (REQUIRED, String) - Y coordinate

```
Signature-Key: sig=hwk;kty="EC";crv="P-256";x="f83OJ3D...";y="x_FEzRu..."
```

RSA:

- `kty` (REQUIRED, String) - "RSA"

- `n` (REQUIRED, String) - Modulus

- `e` (REQUIRED, String) - Exponent

```
Signature-Key: sig=hwk;kty="RSA";n="0vx7agoebGcQ...";e="AQAB"
```

**Constraints:**

- The `alg` parameter MUST NOT be present (algorithm is specified in Signature-Input)

- The `kid` parameter SHOULD NOT be used

> **Design Note:** The hwk parameters use structured field strings rather than byte sequences. JWK key values are base64url-encoded per [@!RFC7517], while structured field byte sequences use base64 encoding per [@!RFC8941]. Using strings allows implementations to pass JWK values directly without converting between base64url and base64, avoiding a potential source of encoding bugs.

**Use cases:**

- Privacy-preserving agents that avoid identity disclosure

- Experimental or temporary access without registration

- Rate limiting and reputation building on a per-key basis

## JWKS URI Discovery (jwks_uri)

The jwks_uri scheme identifies the signer and enables key discovery via a metadata document containing a `jwks_uri` property.

**Parameters:**

- `id` (REQUIRED, String) - Signer identifier (HTTPS URL)

- `dwk` (REQUIRED, String) - Dot well-known metadata document name under `/.well-known/`

- `kid` (REQUIRED, String) - Key identifier

**Discovery procedure:**

1. Fetch `{id}/.well-known/{dwk}`

2. Parse as JSON metadata

3. Extract `jwks_uri` property

4. Fetch JWKS from `jwks_uri`

5. Find key with matching `kid`

**Example:**

```
Signature-Key: sig=jwks_uri;id="https://agent.example";dwk="aauth-agent";kid="key-1"
```

**Use cases:**

- Identified services with stable HTTPS identity

- Search engine crawlers and monitoring services

- Services requiring explicit entity identification

## X.509 Certificates (x509)

The x509 scheme provides certificate-based verification using PKI trust chains.

**Parameters:**

- `x5u` (REQUIRED, String) - URL to X.509 certificate chain (PEM format, [@!RFC7517] Section 4.6)

- `x5t` (REQUIRED, Byte Sequence) - Certificate thumbprint: SHA-256 hash of DER-encoded end-entity certificate

**Verification procedure:**

1. Check cache for certificate with matching `x5t`

2. If not cached or expired, fetch PEM from `x5u`

3. Validate certificate chain to trusted root CA

4. Check certificate validity and revocation status

5. Verify `x5t` matches end-entity certificate

6. Extract public key from end-entity certificate

7. Verify signature using extracted key

8. Cache certificate indexed by `x5t`

**Example:**

```
Signature-Key: sig=x509;x5u="https://agent.example/.well-known/cert.pem";x5t=:bWcoon4QTVn8Q6xiY0ekMD6L8bNLMkuDV2KtvsFc1nM=:
```

**Use cases:**

- Enterprise environments with PKI infrastructure

- Integration with existing certificate management systems

- Scenarios requiring certificate revocation checking

- Regulated industries requiring certificate-based authentication

## JWT Confirmation Key (jwt)

The jwt scheme embeds a public key inside a signed JWT using the `cnf` (confirmation) claim [@!RFC7800], enabling delegation and horizontal scale.

**Parameters:**

- `jwt` (REQUIRED, String) - Compact-serialized JWT

**JWT requirements:**

- MUST contain `iss` claim (HTTPS URL of the issuer)

- MUST contain `dwk` claim (dot well-known metadata document name) — the verifier constructs `{iss}/.well-known/{dwk}` to discover the issuer's `jwks_uri`

- MUST contain `cnf.jwk` claim with embedded JWK

- SHOULD contain standard claims: `sub`, `exp`, `iat`

- Verifiers SHOULD verify the JWT `typ` header parameter has an expected value per deployment policy

> **Note:** The mechanism by which the JWT is obtained is out of scope of this specification.

**Verification procedure:**

1. Verify the JWT `typ` header parameter has an expected value per policy. Reject if unexpected.

2. Extract `iss` and `dwk` claims from the JWT payload

3. Fetch `{iss}/.well-known/{dwk}`, parse as JSON metadata, extract `jwks_uri`

4. Fetch JWKS from `jwks_uri`, find key matching `kid` in JWT header

5. Verify JWT signature using the discovered key

6. Validate JWT claims per policy (`iss`, `exp`, etc.)

7. Extract JWK from `cnf.jwk`

8. Verify HTTP Message Signature using extracted key

**Example:**

```
Signature-Key: sig=jwt;jwt="eyJhbGciOiJFUzI1NiI..."
```

**JWT payload example:**

```json
{
  "iss": "https://issuer.example",
  "dwk": "oauth-authorization-server",
  "sub": "instance-123",
  "exp": 1732210000,
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
    }
  }
}
```

**Use cases:**

- Distributed services with ephemeral instance keys

- Delegation scenarios where instances act on behalf of an authority

- Short-lived credentials for horizontal scaling

## JKT JWT Self-Issued Key Delegation (jkt-jwt)

The jkt-jwt scheme (pronounced "jacket jot") provides self-issued key delegation using a JWT whose signing key is embedded in the JWT header. This enables devices with hardware-backed secure enclaves to delegate signing authority to ephemeral keys, avoiding the performance cost of repeated enclave operations while maintaining a cryptographic chain of trust rooted in the enclave key.

Many devices — mobile phones, laptops, IoT hardware — include secure enclaves or trusted execution environments (e.g., Apple Secure Enclave, Android StrongBox, TPM) that can generate and store private keys with strong protection guarantees. However, signing operations using these enclaves are comparatively slow and may require user interaction (biometric confirmation, PIN entry).

For HTTP Message Signatures, where every request requires a signature, this creates a tension between security and performance. The jkt-jwt scheme resolves this by allowing the enclave key to sign a JWT that delegates authority to a faster ephemeral key:

1. The enclave generates a long-lived key pair (the identity key)
2. The device generates an ephemeral key pair in software (the signing key)
3. The enclave signs a JWT binding the ephemeral key via the `cnf` claim
4. HTTP requests are signed with the fast ephemeral key
5. The JWT proves the ephemeral key was authorized by the enclave key

The enclave key's JWK Thumbprint URI (`urn:jkt:<hash-algorithm>:<thumbprint>`) serves as a stable, pseudonymous device identity. Verifiers build trust in this identity over time (TOFU — Trust On First Use).

**Parameters:**

- `jwt` (REQUIRED, String) - Compact-serialized JWT

**JWT requirements:**

Header:

- `typ` (REQUIRED) - Identifies the thumbprint hash algorithm. Defined values: `jkt-s256+jwt` (SHA-256), `jkt-s512+jwt` (SHA-512). Implementations MUST support `jkt-s256+jwt` and MAY support additional algorithms.

- `alg` (REQUIRED) - Signature algorithm used by the enclave key

- `jwk` (REQUIRED) - JWK public key of the enclave/identity key (the key that signed this JWT)

Payload:

- `iss` (REQUIRED) - JWK Thumbprint URI of the signing key, in the format `urn:jkt:<hash-algorithm>:<thumbprint>` where the thumbprint is computed per [@!RFC7638]. The hash algorithm in the URN MUST match the algorithm indicated by the JWT `typ`. The verifier knows the hash algorithm from the `typ` it accepted, computes the thumbprint of the header `jwk`, prepends the known `urn:jkt:<hash-algorithm>:` prefix, and compares to `iss` by string equality.

- `iat` (REQUIRED) - Issued-at timestamp

- `exp` (REQUIRED) - Expiration timestamp

- `cnf` (REQUIRED) - Confirmation claim [@!RFC7800] containing `jwk`: the ephemeral public key delegated for HTTP message signing

The `sub` claim is not used. The identity is the enclave key itself, fully represented by the `iss` thumbprint.

**JWT Type Values:**

The `typ` value encodes both the purpose and the thumbprint hash algorithm:

| `typ` | Hash Algorithm | `iss` prefix |
|---|---|---|
| `jkt-s256+jwt` | SHA-256 | `urn:jkt:sha-256:` |
| `jkt-s512+jwt` | SHA-512 | `urn:jkt:sha-512:` |

The `jkt-` prefix indicates a self-issued delegation JWT: the signing key is embedded in the JWT header as a JWK, the issuer is identified by the key's thumbprint, and the JWT delegates signing authority to the key in the `cnf` claim. The suffix (`s256`, `s512`) identifies the hash algorithm used for the thumbprint. The `typ` and `iss` prefix MUST be consistent.

These types are independent of the Signature-Key header and MAY be used in other contexts where self-issued key delegation is needed. Additional hash algorithms can be supported by registering new `typ` values following the `jkt-<alg>+jwt` pattern.

**Example:**

```
Signature-Key: sig=jkt-jwt;jwt="eyJ..."
```

JWT header:

```json
{
  "typ": "jkt-s256+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
  }
}
```

JWT payload:

```json
{
  "iss": "urn:jkt:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "iat": 1732210000,
  "exp": 1732296400,
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
    }
  }
}
```

In this example, the enclave holds a P-256 key (signed via hardware) and delegates to an Ed25519 ephemeral key (signed in software). The identity is `urn:jkt:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`.

**Verification procedure:**

1. Parse the JWT without verifying the signature

2. Check the `typ` header (e.g., `jkt-s256+jwt`). Reject if the type is not supported.

3. Determine the hash algorithm and `iss` prefix from the `typ` (e.g., `jkt-s256+jwt` → SHA-256, `urn:jkt:sha-256:`)

4. Extract the `jwk` from the JWT header

5. Compute the JWK Thumbprint ([@!RFC7638]) of the header `jwk` using the determined hash algorithm

6. Construct the expected `iss` value by prepending the known prefix to the computed thumbprint

7. Verify the `iss` claim matches the constructed value by string equality

8. Verify the JWT signature using the header `jwk`

9. Validate `exp` and `iat` claims per policy

10. Extract the ephemeral public key from `cnf.jwk`

11. Verify the HTTP Message Signature using the ephemeral key

**Use cases:**

- Devices with hardware-backed secure enclaves delegating to fast ephemeral keys

- Persistent pseudonymous identity without requiring registration or authority

- Mobile apps, laptops, and IoT devices with enclave-backed identity

# Security Considerations

## Key Validation

Verifiers MUST validate all cryptographic material before use:

- **hwk**: Validate JWK structure and key parameters

- **jwks_uri**: Verify HTTPS transport and validate fetched JWKS

- **x509**: Validate complete certificate chain, check revocation status

- **jwt**: Verify JWT signature and validate embedded JWK

- **jkt-jwt**: Verify JWT signature using header `jwk`, validate thumbprint matches `iss`, validate embedded ephemeral JWK

## Caching and Performance

Verifiers MAY cache keys to improve performance but MUST implement appropriate cache expiration:

- **jwks_uri**: Respect cache-control headers, implement reasonable TTLs

- **x509**: Cache by `x5t`, invalidate on certificate expiry

- **jwt**: Cache embedded keys until JWT expiration

- **jkt-jwt**: Cache embedded keys until JWT expiration; cache by `iss` thumbprint URI

Verifiers SHOULD implement cache limits to prevent resource exhaustion attacks.

## Scheme-Specific Risks

**hwk**: No identity verification - suitable only for scenarios where pseudonymous access is acceptable.

**jwks_uri**: Relies on HTTPS security - vulnerable to DNS/CA compromise. Verifiers should implement certificate pinning where appropriate.

**x509**: Requires robust certificate validation including revocation checking. Verifiers MUST NOT skip certificate chain validation.

**jwt**: Delegation trust depends on JWT issuer verification. Verifiers MUST validate JWT signatures and claims before trusting embedded keys.

**jkt-jwt**: The security of this scheme depends on the enclave key's private key remaining protected in hardware. If the enclave key is compromised, all delegated ephemeral keys are compromised. Verifiers should be aware that the jkt-jwt scheme implies but does not prove hardware protection — there is no attestation mechanism in this scheme. Unlike the `jwt` scheme where trust is rooted in a discoverable issuer, jkt-jwt trust is rooted in the key itself. Verifiers MUST understand that any party can create a jkt-jwt — the scheme provides pseudonymous identity, not verified identity. The `exp` claim on the JWT controls how long the ephemeral key is valid. Shorter lifetimes limit the exposure window if an ephemeral key is compromised. Implementations SHOULD use the shortest practical lifetime. The `iss` value is a JWK Thumbprint URI — a globally unique, collision-resistant identifier. The verifier MUST always compute the expected `iss` from the header `jwk` and compare by string equality — never trust the `iss` value alone.

## Algorithm Selection

The `alg` parameter in Signature-Input (RFC 9421) determines the signature algorithm. Verifiers MUST:

- Validate algorithm against policy (reject weak algorithms)

- Ensure key type matches algorithm requirements

- Reject algorithm/key mismatches

## Signature-Key Integrity

The Signature-Key header SHOULD be included as a covered component in Signature-Input:

```
Signature-Input: sig=("@method" "@authority" "@path" "signature-key"); created=1732210000
```

If `signature-key` is not covered, an attacker can modify the header without invalidating the signature. Attacks include:

**Scheme substitution**: An attacker extracts the public key from an `hwk` scheme and republishes it via `jwks_uri` under their own identity, causing verifiers to attribute the request to the attacker.

**Identity substitution**: An attacker modifies the `id` parameter in a `jwks_uri` scheme to point to their own metadata endpoint that returns the same public key, impersonating a different signer.

Verifiers SHOULD reject requests where `signature-key` is not a covered component.

# Privacy Considerations

## Pseudonymity vs. Identity

The hwk scheme enables pseudonymous operation where the signer's identity is not disclosed. Verifiers should be aware that:

- hwk provides no identity linkage across requests (unless keys are reused)

- Key reuse enables tracking but may be necessary for reputation/rate-limiting

- Verifiers should not log or retain hwk keys beyond operational necessity

The jkt-jwt scheme is pseudonymous like hwk — the identity is a key thumbprint URI. However, because the thumbprint is stable across sessions (tied to the enclave key), it enables long-term tracking. Verifiers should apply the same retention considerations as for hwk keys.

The jwks_uri, x509, and jwt schemes all reveal signer identity. Protocols using these schemes should inform signers that their identity will be disclosed to verifiers.

## Key Discovery Tracking

The jwks_uri and x509 schemes require verifiers to fetch resources from signer-controlled URLs. This creates potential tracking vectors:

- Signers can observe when and from where keys are fetched

- Verifiers should cache keys to minimize fetches

- Verifiers may wish to use shared caching infrastructure to reduce fingerprinting

## JWT Contents

JWTs in the jwt scheme may contain additional claims beyond `cnf`. Verifiers should:

- Only process claims necessary for verification

- Not log or retain unnecessary JWT claims

- Be aware that JWT contents are visible to network observers unless using TLS

# IANA Considerations

## HTTP Field Name Registration

This document registers the Signature-Key header field in the "Hypertext Transfer Protocol (HTTP) Field Name Registry" defined in [@!RFC9110].

Header field name: Signature-Key

Applicable protocol: http

Status: standard

Author/Change controller: IETF

Specification document(s): [this document]

## Signature-Key Scheme Registry

This document establishes the "HTTP Signature-Key Scheme" registry. This registry allows for the definition of additional key distribution schemes beyond those defined in this document.

### Registration Procedure

New scheme registrations require Specification Required per [@!RFC8126].

### Initial Registry Contents

| Scheme | Description | Reference |
|--------|-------------|-----------|
| hwk | Header Web Key - inline public key | [this document] |
| jwks_uri | JWKS URI Discovery - key discovery via metadata | [this document] |
| x509 | X.509 Certificate - PKI certificate chain | [this document] |
| jwt | JWT Confirmation Key - delegated key in JWT | [this document] |
| jkt-jwt | JKT JWT Self-Issued Key Delegation - enclave-backed delegation | [this document] |

### Registration Template

Scheme Name:
: The token value used in the Signature-Key header

Description:
: A brief description of the scheme

Specification:
: Reference to the specification defining the scheme

Parameters:
: List of parameters defined for this scheme

{backmatter}

# Document History

*Note: This section is to be removed before publishing as an RFC.*


## draft-hardt-httpbis-signature-key-02

- Changed x5t parameter to byte sequence per reviewer feedback
- Added structured field types to all parameters
- Added design note explaining string vs byte sequence choice for hwk

## draft-hardt-httpbis-signature-key-01

- Initial public draft with four schemes: hwk, jwks_uri, x509, jwt

# Design Rationale

## Why a Separate Header?

An alternative design would extend Signature-Input with additional parameters to carry key material. This was considered and rejected for several reasons:

1. **Parameter complexity**: Each scheme has a different set of parameters (e.g., `hwk` needs `kty`, `crv`, `x`, `y`; `jwks_uri` needs `id`, `dwk`, `kid`; `jwt` needs a full JWT string). Overloading Signature-Input with all possible key parameters across all schemes would make the Signature-Input grammar unwieldy and harder to parse.

2. **Separation of concerns**: Signature-Input describes *what* is signed and *how* (covered components, algorithm, timestamps). Signature-Key describes *who* signed it and *where to find the key*. These are distinct concerns, and separating them into distinct headers makes each easier to understand and process independently.

3. **Extensibility**: A separate header with a scheme registry allows new key distribution mechanisms to be added without modifying the Signature-Input grammar. New schemes can define arbitrary parameters without coordination with RFC 9421.

4. **Multiple signatures**: With a dictionary structure keyed by label, each signature can use a different scheme. This is natural in a separate header but would create complex nesting if embedded in Signature-Input.

## Why Schemes Instead of Just a Key and Key ID?

A simpler design would define Signature-Key as carrying only a public key (or key reference) and a key identifier, without the scheme abstraction. This was considered insufficient because:

1. **Trust model varies**: A bare key tells the verifier nothing about the trust model. Is this a pseudonymous key to be evaluated on its own merits (hwk)? A key bound to a discoverable identity (jwks_uri)? A delegated key from an authority (jwt)? A certificate-backed key (x509)? The scheme token tells the verifier which verification procedure to follow and what trust properties the key carries.

2. **Verification procedure differs**: Each scheme has a fundamentally different verification path. `hwk` requires no external fetches. `jwks_uri` requires metadata discovery. `x509` requires certificate chain validation. `jwt` requires JWT signature verification before the HTTP signature can be verified. A key-and-ID-only design would push scheme detection to heuristics or out-of-band agreement.

3. **Security properties differ**: Without an explicit scheme, a verifier cannot distinguish between a self-asserted key and a CA-certified key. The scheme makes the trust model explicit, allowing verifiers to enforce policy (e.g., "only accept `jwt` or `x509` schemes").

4. **Interoperability**: Explicit schemes create clear interoperability targets. Two implementations that support the `jwt` scheme know exactly what to expect from each other. Without schemes, the same key material could be interpreted differently by different implementations.

## Why jwks_uri Instead of Inline JWKS?

The `jwks_uri` and `jwt` schemes reference a `jwks_uri` property in the `.well-known` metadata document rather than embedding the JWKS directly in the metadata. This separation of concerns is deliberate:

1. **Independent key rotation**: Keys can be rotated by updating the JWKS endpoint without modifying the `.well-known` metadata document. This decouples key lifecycle management from configuration management, allowing operations teams to rotate keys on their own schedule without redeploying metadata.

2. **Independent management**: The `.well-known` metadata document and the JWKS can be hosted, managed, and secured by different systems or teams. For example, an identity team may manage keys while a platform team manages service metadata.

3. **Caching semantics**: The JWKS endpoint can have its own cache-control headers tuned for key rotation frequency (e.g., short TTLs during a rotation event), independent of the `.well-known` document's caching policy.

4. **Consistency with existing standards**: This approach mirrors the pattern established by OpenID Connect Discovery [@?OpenID.Discovery] and OAuth Authorization Server Metadata [@?RFC8414], which both use `jwks_uri` in metadata documents for the same reasons.

# Acknowledgments

TBD
%%%
title = "HTTP Signature Headers"
abbrev = "Signature-Headers"
ipr = "trust200902"
area = "Applications and Real-Time"
workgroup = "HTTP"
keyword = ["http", "signature", "authentication", "jwk", "jwt"]

[seriesInfo]
status = "standard"
name = "Internet-Draft"
value = "draft-hardt-httpbis-signature-key-latest"
stream = "IETF"

date = 2026-04-05T00:00:00Z

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

<reference anchor="x402" target="https://docs.x402.org">
  <front>
    <title>x402: HTTP 402 Payment Protocol</title>
    <author>
      <organization>x402 Foundation</organization>
    </author>
    <date year="2025"/>
  </front>
</reference>

<reference anchor="OpenID.Discovery" target="https://openid.net/specs/openid-connect-discovery-1_0.html">
  <front>
    <title>OpenID Connect Discovery 1.0</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization>NRI</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization>Ping Identity</organization>
    </author>
    <author initials="M." surname="Jones" fullname="Michael B. Jones">
      <organization>Microsoft</organization>
    </author>
    <author initials="E." surname="Jay" fullname="Edmund Jay">
      <organization>Illumila</organization>
    </author>
    <date year="2014" month="November"/>
  </front>
</reference>

.# Abstract

This document defines three HTTP header fields for use with HTTP Message Signatures as defined in RFC 9421. The Signature-Key header distributes public keys used to verify signatures, with five initial key distribution schemes: pseudonymous inline keys (hwk), self-issued key delegation via JWK Thumbprint JWTs (jkt-jwt), identified signers with JWKS URI discovery (jwks_uri), JWT-based delegation (jwt), and X.509 certificate chains (x509). The Signature-Requirement response header enables servers to request signed requests at different trust levels — pseudonymous key possession or verified identity — and supports incremental adoption via 401, 402, and 429 status codes. The Signature-Error response header provides structured error information when signature verification fails. Together, these headers enable flexible trust models ranging from privacy-preserving pseudonymous verification to horizontally-scalable delegated authentication and PKI-based identity chains.

.# Discussion Venues

*Note: This section is to be removed before publishing as an RFC.*

Source for this draft and an issue tracker can be found at https://github.com/dickhardt/signature-key.

{mainmatter}

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Introduction

HTTP Message Signatures [@!RFC9421] provides a powerful mechanism for creating and verifying digital signatures over HTTP messages. To verify a signature, the verifier needs the signer's public key. While RFC 9421 defines signature creation and verification procedures, it intentionally leaves key distribution to application protocols, recognizing that different deployments have different trust requirements.

This document defines three HTTP header fields:

- **Signature-Key** ([Signature-Key HTTP Request Header](#signature-key-http-request-header)) distributes public keys for HTTP Message Signature verification. The header supports five schemes, each designed for different trust models and operational requirements:

  1. **Header Web Key (hwk)** - Self-contained public keys for pseudonymous verification
  2. **JKT JWT (jkt-jwt)** - Self-issued key delegation via JWK Thumbprint JWTs ("jacket jot")
  3. **JWKS URI (jwks_uri)** - Identified signers with key discovery via metadata
  4. **JWT (jwt)** - Delegated keys embedded in signed JWTs for horizontal scale
  5. **X.509 (x509)** - Certificate-based verification with PKI trust chains

  Additional schemes may be defined through the IANA registry established by this document.

- **Signature-Requirement** ([Signature-Requirement HTTP Response Header](#signature-requirement-http-response-header)) enables servers to request signed requests at different trust levels — pseudonymous key possession or verified identity. The header supports incremental adoption via 401, 402, and 429 status codes, and coexists with `WWW-Authenticate` for backward compatibility with legacy clients.

- **Signature-Error** ([Signature-Error HTTP Response Header](#signature-error-http-response-header)) provides structured error information when signature verification fails, enabling clients to diagnose and correct signing issues.

The Signature-Key header works in conjunction with the Signature-Input and Signature headers defined in RFC 9421, using matching labels to correlate signature metadata with keying material. The Signature-Requirement and Signature-Error response headers are independent of the label mechanism.

# Signature-Key HTTP Request Header

The `Signature-Key` header provides the public key or key reference needed to verify an HTTP Message Signature. It is a Structured Field Dictionary [@!RFC8941] keyed by signature label, where each member describes how to obtain the verification key for the corresponding signature.

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
Signature-Key: sig1=jwt;jwt="eyJ...", sig2=jwks_uri;id="https://example.com";dwk="eg-config";kid="k1"
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

- The `alg` parameter MUST NOT be present (algorithm is derived from the key type and curve)

- The `kid` parameter SHOULD NOT be used

**Use cases:**

- Privacy-preserving agents that avoid identity disclosure

- Experimental or temporary access without registration

- Rate limiting and reputation building on a per-key basis

## JKT JWT Self-Issued Key Delegation (jkt-jwt)

The jkt-jwt scheme (pronounced "jacket jot") provides self-issued key delegation using a JWT whose signing key is embedded in the JWT header. This enables devices with hardware-backed secure enclaves to delegate signing authority to ephemeral keys, avoiding the performance cost of repeated enclave operations while maintaining a cryptographic chain of trust rooted in the enclave key.

Many devices — mobile phones, laptops, IoT hardware — include secure enclaves or trusted execution environments (e.g., Apple Secure Enclave, Android StrongBox, TPM) that can generate and store private keys with strong protection guarantees. However, signing operations using these enclaves are comparatively slow and may require user interaction (biometric confirmation, PIN entry).

For HTTP Message Signatures, where every request requires a signature, this creates a tension between security and performance. The jkt-jwt scheme resolves this by allowing the enclave key to sign a JWT that delegates authority to a faster ephemeral key:

1. The enclave generates a long-lived key pair (the identity key)
2. The device generates an ephemeral key pair in software (the signing key)
3. The enclave signs a JWT binding the ephemeral key via the `cnf` claim
4. HTTP requests are signed with the fast ephemeral key
5. The JWT proves the ephemeral key was authorized by the enclave key

The enclave key's JWK Thumbprint URI (`urn:jkt:<hash-algorithm>:<thumbprint>`) serves as a stable, pseudonymous device identity. Verifiers build trust in this identity over time (TOFU — Trust On First Use [@?RFC7435]).

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
Signature-Key: sig=jwks_uri;id="https://client.example";dwk="example-configuration";kid="key-1"
```

**Use cases:**

- Identified services with stable HTTPS identity

- Search engine crawlers and monitoring services

- Services requiring explicit entity identification

## JWT Confirmation Key (jwt)

The jwt scheme embeds a public key inside a signed JWT using the `cnf` (confirmation) claim [@!RFC7800], enabling delegation and horizontal scale.

**Parameters:**

- `jwt` (REQUIRED, String) - Compact-serialized JWT

**JWT requirements:**

- MUST contain `cnf.jwk` claim with embedded JWK

- SHOULD contain `iss` claim (HTTPS URL of the issuer) — using SHOULD rather than MUST allows existing JWT infrastructure to be used without modification

- SHOULD contain `dwk` claim (dot well-known metadata document name) — the verifier constructs `{iss}/.well-known/{dwk}` to discover the issuer's `jwks_uri`. Using SHOULD allows deployments where the verifier already knows the issuer's keys.

- SHOULD contain standard claims: `sub`, `exp`, `iat`

- Verifiers SHOULD verify the JWT `typ` header parameter has an expected value per deployment policy, to optimize for a quick rejection

> **Note:** The mechanism by which the JWT is obtained is out of scope of this specification.

**Verification procedure:**

1. Parse the JWT parameter value per [@!RFC7519] Section 7.2. Reject if the value is not a well-formed JWT. This and subsequent pre-signature checks allow the verifier to fail early without expensive cryptographic operations or network fetches.

2. Verify the JWT `typ` header parameter has an expected value per policy. Reject if unexpected.

3. Validate `exp` claim if present. Reject if the token has expired.

4. Verify required claims are present (`cnf.jwk`, plus any claims required by deployment policy). Reject if a required claim is missing.

5. If `iss` and `dwk` claims are present, fetch `{iss}/.well-known/{dwk}`, parse as JSON metadata, extract `jwks_uri`. Fetch JWKS from `jwks_uri`, find key matching `kid` in JWT header. If `iss` or `dwk` is absent, the verifier MUST obtain the issuer's key through an application-specific mechanism.

6. Verify JWT signature using the discovered key

7. Validate remaining JWT claims per policy (`iss`, `sub`, etc.)

8. Extract JWK from `cnf.jwk`

9. Verify HTTP Message Signature using extracted key

**Example:**

```
Signature-Key: sig=jwt;jwt="eyJhbGciOiJFUzI1NiI..."
```

**JWT payload example:**

```json
{
  "iss": "https://issuer.example",
  "dwk": "example-configuration",
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
Signature-Key: sig=x509;x5u="https://client.example/.well-known/cert.pem";x5t=:bWcoon4QTVn8Q6xiY0ekMD6L8bNLMkuDV2KtvsFc1nM=:
```

**Use cases:**

- Enterprise environments with PKI infrastructure

- Integration with existing certificate management systems

- Scenarios requiring certificate revocation checking

- Regulated industries requiring certificate-based authentication

# Signature-Requirement HTTP Response Header

The `Signature-Requirement` header indicates that a request must be signed. It is a Dictionary ([@!RFC8941], Section 3.2) with the following members:

- `requirement` (REQUIRED): A Token ([@!RFC8941], Section 3.3.4) indicating the requirement level.
- `algorithms` (OPTIONAL): An Inner List of String ([@!RFC8941], Section 3.1.1) listing accepted signing algorithms. Values are JSON Web Signature algorithm identifiers from the IANA JSON Web Signature and Encryption Algorithms registry ([@!RFC7518], Section 3.1), e.g., `"EdDSA"`, `"ES256"`. When the x509 scheme is used, the algorithm is determined by the certificate's public key; the `algorithms` parameter constrains which certificate key types are acceptable.
- `required_input` (OPTIONAL): An Inner List of String ([@!RFC8941], Section 3.1.1) listing the covered components the server requires in Signature-Input. Including this parameter allows a client to construct a valid signed request without an additional round trip. If absent, the client signs with its default covered components and learns of any missing components from a `Signature-Error` response with `error=invalid_input`. This member uses the same name and format as the `required_input` member in `Signature-Error` ([Error Codes](#error-codes)).

Additional members are defined per requirement level by the specification that registers the level. Recipients MUST ignore unknown members.

## Requirement Levels

| Level | Meaning |
|-------|---------|
| `pseudonym` | Signed request proving key possession (hwk or jkt-jwt scheme) |
| `identity` | Verified client identity (jwks_uri, jwt, or x509 scheme) |

Additional levels may be registered through the IANA registry established by this document.

## Response Status Codes

The `Signature-Requirement` header MAY be sent with the following status codes:

| Status | Meaning | Legacy client behavior | Signature-aware client behavior |
|--------|---------|----------------------|-------------------------------|
| `401` | Authentication required | Falls back to WWW-Authenticate | Signs request at required level |
| `402` | Payment + authentication required | Processes payment mechanism | Signs request AND processes payment |
| `429` | Rate limited | Respects Retry-After, slows down | Signs request, gets higher per-key rate limit |

The `429` case is particularly important for incremental adoption: a server can add `Signature-Requirement` to its existing 429 responses with zero risk. Legacy clients ignore the unknown header and respect `Retry-After`. Signature-aware clients sign with a pseudonymous key, giving the server a stable key thumbprint for per-client rate limiting — and the client gets a higher rate limit in return.

## Requirement Level Semantics

### pseudonym

The server requires a signed request using a pseudonymous Signature-Key scheme (hwk or jkt-jwt). The server can track the client by JWK Thumbprint ([@!RFC7638]) without knowing its identity. This is useful for rate limiting anonymous requests, tracking repeat visitors by key thumbprint, spam prevention without requiring verified identity, and hardware-backed pseudonymous identity.

### identity

The server requires verified client identity using an identity Signature-Key scheme (jwks_uri, jwt, or x509). This is useful for API access policies based on known clients, webhook signature verification, and allowlisting trusted clients for elevated rate limits.

If a client already knows the server's requirement level (from a previous interaction or metadata), it MAY sign the initial request directly without waiting for a challenge response.

## Incremental Adoption

`Signature-Requirement` is designed for zero-coordination deployment. The header is unknown to legacy clients and ignored per HTTP semantics — servers can add it to existing responses without breaking anything.

**Stage 1 — Rate limiting (429):** A server adds `Signature-Requirement: requirement=pseudonym` to its 429 responses. Legacy clients slow down as before. Signature-aware clients sign requests and get higher per-key rate limits. The server gains per-client rate limiting without requiring registration or API keys.

**Stage 2 — Authentication (401):** The server starts requiring signatures on some paths, returning 401 with `Signature-Requirement`. It can include `WWW-Authenticate` alongside for legacy clients that have other auth mechanisms. Signature-aware clients sign; legacy clients fall back to bearer tokens or other schemes.

**Stage 3 — Identity (401):** The server upgrades from `pseudonym` to `identity` on sensitive paths, requiring verifiable client identity via `jwks_uri`, `jwt`, or `x509` schemes. The server can now make identity-based policy decisions without pre-registration.

Each stage is independently deployable. A server can use stage 1 on all endpoints while using stage 3 on admin endpoints. No bilateral agreements or client coordination required.

## Coexistence with WWW-Authenticate

`Signature-Requirement` and `WWW-Authenticate` ([@!RFC9110], Section 11.6.1) are independent header fields; a response MAY include both. A client that understands Signature-Key processes `Signature-Requirement`; a legacy client processes `WWW-Authenticate`. Neither header's presence invalidates the other.

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api"
Signature-Requirement: requirement=identity
```

A `402` response MAY include a payment mechanism such as x402 [@?x402] or the Micropayment Protocol ([@?I-D.ryan-httpauth-payment]) alongside `Signature-Requirement` for authentication:

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment id="x7Tg2pLq", method="example",
    request="eyJhbW91bnQiOiIxMDAw..."
Signature-Requirement: requirement=pseudonym
```

## Examples

Pseudonymous access:

```http
HTTP/1.1 401 Unauthorized
Signature-Requirement: requirement=pseudonym
```

Identity with algorithm restriction and required components:

```http
HTTP/1.1 401 Unauthorized
Signature-Requirement: requirement=identity, algorithms=("EdDSA" "ES256"),
    required_input=("@method" "@authority" "@path" "signature-key")
```

Rate limiting with pseudonymous upgrade:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 30
Signature-Requirement: requirement=pseudonym
```

Payment with pseudonymous authentication:

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment id="x7Tg2pLq", method="example",
    request="eyJhbW91bnQiOiIxMDAw..."
Signature-Requirement: requirement=pseudonym
```

## Client Processing

When a client receives a response containing a `Signature-Requirement` header, it MAY retry the request with an HTTP Message Signature using a Signature-Key scheme appropriate for the indicated requirement level.

When a `429` response includes both `Retry-After` and `Signature-Requirement`, the client MAY retry immediately with a signed request at the indicated requirement level without waiting for the `Retry-After` interval. Signing the request provides a key thumbprint that enables per-client rate limiting, which may result in a higher rate limit for the client.

A server MAY return a `429` response without `Signature-Requirement` to a signed request when it wants to rate-limit the client regardless of signing. In this case, the client MUST respect `Retry-After` as usual.

If the `algorithms` member is present, the client SHOULD use one of the listed algorithms. If the client does not support any of the listed algorithms, it SHOULD NOT retry with a signature.

> **Open Issue:** Should this specification define a baseline HTTP Message Signatures profile (minimum covered components, timestamp requirements, verification steps), or is that always the responsibility of the protocol using these headers? The `required_input` parameter enables runtime discovery, but does not cover server-side verification requirements such as timestamp validation or replay protection. See [GitHub issue #7](https://github.com/dickhardt/signature-key/issues/7).

# Signature-Error HTTP Response Header

When a server rejects a signed request due to a signature-related error, the response SHOULD include the `Signature-Error` header. The response status code is typically `400 Bad Request`, since the signature or keying material is malformed or invalid. A server MAY use `401 Unauthorized` for recoverable errors (e.g., `unsupported_algorithm`, `invalid_input`) where the client can retry with corrected parameters.

## Header Structure

The `Signature-Error` header is a Dictionary ([@!RFC8941], Section 3.2) with the following member:

- `error` (REQUIRED): A Token ([@!RFC8941], Section 3.3.4) indicating the error code.

Additional members are defined per error code. Recipients MUST ignore unknown members.

```http
Signature-Error: error=unsupported_algorithm,
    supported_algorithms=("EdDSA" "ES256")
```

The response body is OPTIONAL and MAY contain a human-readable description in any content type. The client MUST NOT depend on the response body for error handling — all machine-readable error information is in the header.

## Error Codes {#error-codes}

### invalid_request

The request is malformed or missing required information unrelated to signature verification — such as missing query parameters or an unsupported content type.

```http
Signature-Error: error=invalid_request
```

### invalid_input

The Signature-Input is missing required covered components.

- `required_input` (OPTIONAL): An Inner List of String ([@!RFC8941], Section 3.1.1) listing the covered components the server requires. The response SHOULD include this member.

```http
Signature-Error: error=invalid_input,
    required_input=("@method" "@authority" "@path"
    "signature-key" "content-digest")
```

### invalid_signature

The HTTP Message Signature is missing, malformed, or cryptographic verification failed. This includes missing `Signature`, `Signature-Input`, or `Signature-Key` headers, an expired `created` timestamp, or a signature that does not verify.

```http
Signature-Error: error=invalid_signature
```

### unsupported_algorithm

The signing algorithm used by the client is not supported by the server.

- `supported_algorithms` (REQUIRED): An Inner List of String ([@!RFC8941], Section 3.1.1) listing the algorithms the server accepts. The response MUST include this member.

```http
Signature-Error: error=unsupported_algorithm,
    supported_algorithms=("EdDSA" "ES256")
```

### invalid_key

The public key in `Signature-Key` could not be parsed, is expired, or does not meet the server's trust requirements.

```http
Signature-Error: error=invalid_key
```

### unknown_key

The public key from `Signature-Key` does not match any key at the client's `jwks_uri` (applicable when the client uses `scheme=jwks_uri`). The server SHOULD re-fetch the JWKS once before returning this error, to handle key rotation.

```http
Signature-Error: error=unknown_key
```

### invalid_jwt

The JWT in the `Signature-Key` header (when using `scheme=jwt` or `scheme=jkt-jwt`) is malformed or its signature verification failed.

```http
Signature-Error: error=invalid_jwt
```

### expired_jwt

The JWT in the `Signature-Key` header (when using `scheme=jwt` or `scheme=jkt-jwt`) has expired (`exp` claim is in the past).

```http
Signature-Error: error=expired_jwt
```

## Access Denied

When the server successfully verifies the client's signature and identity but denies access based on policy (e.g., the client is not authorized for this resource), the server returns `403 Forbidden`. This is not a signature error — the authentication succeeded but authorization was denied. The response MUST NOT include a `Signature-Requirement` or `Signature-Error` header.

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

**jkt-jwt**: The security of this scheme depends on the enclave key's private key remaining protected in hardware. If the enclave key is compromised, all delegated ephemeral keys are compromised. Verifiers should be aware that the jkt-jwt scheme implies but does not prove hardware protection — there is no attestation mechanism in this scheme. Unlike the `jwt` scheme where trust is rooted in a discoverable issuer, jkt-jwt trust is rooted in the key itself. Verifiers MUST understand that any party can create a jkt-jwt — the scheme provides pseudonymous identity, not verified identity. The `exp` claim on the JWT controls how long the ephemeral key is valid. Shorter lifetimes limit the exposure window if an ephemeral key is compromised. Implementations SHOULD use the shortest practical lifetime. The `iss` value is a JWK Thumbprint URI — a globally unique, collision-resistant identifier. The verifier MUST always compute the expected `iss` from the header `jwk` and compare by string equality — never trust the `iss` value alone.

**jwks_uri**: Relies on HTTPS security - vulnerable to DNS/CA compromise. Verifiers should implement certificate pinning where appropriate.

**jwt**: Delegation trust depends on JWT issuer verification. Verifiers MUST validate JWT signatures and claims before trusting embedded keys.

**x509**: Requires robust certificate validation including revocation checking. Verifiers MUST NOT skip certificate chain validation.

## Algorithm Selection

The signature algorithm is determined by the key material in Signature-Key, not by the optional `alg` parameter in Signature-Input ([@!RFC9421], Section 2.3). For JWK-based schemes (hwk, jkt-jwt, jwks_uri, jwt), the algorithm is identified by the key type and curve (`kty` + `crv`) or by the `alg` parameter in the JWK ([@!RFC7517]). For the x509 scheme, the algorithm is determined by the certificate's public key type.

If the `alg` parameter is present in Signature-Input, verifiers MUST verify it is consistent with the key material. If it is absent, verifiers derive the algorithm from the key.

Verifiers MUST:

- Validate the algorithm against policy (reject weak algorithms)

- Ensure the key type is consistent with the derived algorithm

- Reject keys whose type does not match an acceptable algorithm

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

The hwk and jkt-jwt schemes enable pseudonymous operation where the signer's identity is not disclosed. Verifiers should be aware that:

- A server can track a client across requests by JWK Thumbprint ([@!RFC7638]). If a client uses the same key across multiple servers, those servers could correlate the client's activity. Clients MUST use distinct keys for distinct servers to prevent cross-server correlation of pseudonymous identity.

- The jkt-jwt thumbprint is stable across sessions (tied to the enclave key), enabling long-term tracking even when ephemeral keys rotate.

- Verifiers should not log or retain pseudonymous keys beyond operational necessity.

The jwks_uri, x509, and jwt schemes reveal signer identity. When a client presents its identity via these schemes, the server learns the client's HTTPS URL or certificate subject, revealing which software is making the request. Servers SHOULD NOT disclose client identity information to third parties without the client operator's consent.

## Key Discovery Tracking

The jwks_uri, jwt, and x509 schemes require verifiers to fetch resources from signer-controlled URLs. This creates tracking vectors:

- Signers can observe when and from where keys are fetched. In particular, when a server fetches a client's JWKS from `jwks_uri`, the fetch reveals to the JWKS host that someone is verifying signatures for that client.

- Verifiers should cache keys to minimize fetches.

- Verifiers may wish to use shared caching infrastructure to reduce fingerprinting.

## JWT Contents

JWTs in the jwt scheme may contain additional claims beyond `cnf`. Verifiers should:

- Only process claims necessary for verification

- Not log or retain unnecessary JWT claims

- Be aware that JWT contents are visible to network observers unless using TLS

# IANA Considerations

## HTTP Field Name Registration

This document registers the following header fields in the "Hypertext Transfer Protocol (HTTP) Field Name Registry" defined in [@!RFC9110].

Header field name: Signature-Key

Applicable protocol: http

Status: standard

Author/Change controller: IETF

Specification document(s): [this document]

Header field name: Signature-Requirement

Applicable protocol: http

Status: standard

Author/Change controller: IETF

Specification document(s): [this document]

Header field name: Signature-Error

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
| jkt-jwt | JKT JWT Self-Issued Key Delegation - enclave-backed delegation | [this document] |
| jwks_uri | JWKS URI Discovery - key discovery via metadata | [this document] |
| jwt | JWT Confirmation Key - delegated key in JWT | [this document] |
| x509 | X.509 Certificate - PKI certificate chain | [this document] |

### Registration Template

Scheme Name:
: The token value used in the Signature-Key header

Description:
: A brief description of the scheme

Specification:
: Reference to the specification defining the scheme

Parameters:
: List of parameters defined for this scheme

## Signature Requirement Level Registry

This document establishes the "Signature Requirement Level" registry. New values may be registered following the Specification Required policy ([@!RFC8126]).

### Initial Registry Contents

| Value | Description | Reference |
|-------|-------------|-----------|
| `pseudonym` | Signed request proving key possession | [this document] |
| `identity` | Verified client identity | [this document] |

## Signature Error Code Registry

This document establishes the "Signature Error Code" registry. New values may be registered following the Specification Required policy ([@!RFC8126]).

### Initial Registry Contents

| Value | Description | Reference |
|-------|-------------|-----------|
| `invalid_request` | Missing required info unrelated to signature | [this document] |
| `invalid_input` | Missing required covered components | [this document] |
| `invalid_signature` | Signature missing, malformed, or verification failed | [this document] |
| `unsupported_algorithm` | Signing algorithm not supported | [this document] |
| `invalid_key` | Key cannot be parsed or doesn't meet trust requirements | [this document] |
| `unknown_key` | Key not found at jwks_uri | [this document] |
| `invalid_jwt` | JWT malformed or signature verification failed | [this document] |
| `expired_jwt` | JWT expired | [this document] |

{backmatter}

# Document History

*Note: This section is to be removed before publishing as an RFC.*

## draft-hardt-httpbis-signature-key-04

- Added Signature-Requirement header for requesting signed requests (pseudonym and identity levels)
- Added Signature-Error header for structured signature verification error responses (moved from draft-hardt-aauth-headers, renamed from AAuth-Error)
- Added incremental adoption section describing zero-coordination deployment via 429/401/402 status codes
- Added privacy considerations for key thumbprint tracking, agent identity disclosure, and JWKS fetch side channel
- Established Signature Requirement Level Registry and Signature Error Code Registry

## draft-hardt-httpbis-signature-key-03

- Added jkt-jwt scheme for self-issued key delegation
- Renamed `well-known` parameter to `dwk` (dot well-known)
- Added `iss` and `dwk` claims to jwt scheme (SHOULD) for issuer key discovery
- Added early validation step to jwt verification procedure (format, typ, exp checks before network fetches)
- Added TOFU reference (RFC 7435) to jkt-jwt scheme
- Added design rationale for jwks_uri vs inline JWKS
- Moved hwk string vs byte sequence design note to rationale appendix
- Reordered schemes
- Added acknowledgments

## draft-hardt-httpbis-signature-key-02

- Changed x5t parameter to byte sequence per reviewer feedback
- Added structured field types to all parameters
- Added design note explaining string vs byte sequence choice for hwk

## draft-hardt-httpbis-signature-key-01

- Initial public draft with four schemes: hwk, jwks_uri, x509, jwt

# Design Rationale

## Why jwks_uri Instead of Inline JWKS?

The `jwks_uri` and `jwt` schemes reference a `jwks_uri` property in the `.well-known` metadata document rather than embedding the JWKS directly in the metadata. This separation of concerns is deliberate:

1. **Independent key rotation**: Keys can be rotated by updating the JWKS endpoint without modifying the `.well-known` metadata document. This decouples key lifecycle management from configuration management, allowing operations teams to rotate keys on their own schedule without redeploying metadata.

2. **Independent management**: The `.well-known` metadata document and the JWKS can be hosted, managed, and secured by different systems or teams. For example, an identity team may manage keys while a platform team manages service metadata.

3. **Caching semantics**: The JWKS endpoint can have its own cache-control headers tuned for key rotation frequency (e.g., short TTLs during a rotation event), independent of the `.well-known` document's caching policy.

4. **Consistency with existing standards**: This approach mirrors the pattern established by OpenID Connect Discovery [@?OpenID.Discovery] and OAuth Authorization Server Metadata [@?RFC8414], which both use `jwks_uri` in metadata documents for the same reasons.

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

## Why Strings Instead of Byte Sequences for hwk?

The hwk parameters use structured field strings rather than byte sequences. JWK key values are base64url-encoded per [@!RFC7517], while structured field byte sequences use base64 encoding per [@!RFC8941]. Using strings allows implementations to pass JWK values directly without converting between base64url and base64, avoiding a potential source of encoding bugs.

# Acknowledgments

The author would like to thank Yaron Sheffer for their feedback on this specification.

%%%
title = "HTTP Signature Keys"
abbrev = "Signature-Keys"
ipr = "trust200902"
area = "Applications and Real-Time"
workgroup = "HTTP"
keyword = ["http", "signature", "key", "jwk", "jwt"]

[seriesInfo]
status = "standard"
name = "Internet-Draft"
value = "draft-hardt-httpbis-signature-key-latest"
stream = "IETF"

date = 2026-06-17T00:00:00Z

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

This document defines four HTTP header fields for use with HTTP Message Signatures as defined in RFC 9421. The Signature-Key request header distributes public keys used to verify signatures, with seven initial key distribution schemes: pseudonymous inline keys (hwk), self-issued key delegation via JWK Thumbprint JWTs (jkt-jwt), identified signers with JWKS URI discovery (jwks_uri), direct JWKS fetch (jwks), JWT-based delegation (jwt), self-issued JWTs (self-jwt), and X.509 certificate chains (x509). The Accept-Signature-Scheme and Accept-Signature-Alg response headers state the schemes and algorithms a server accepts, so a client can select both before it signs. The Signature-Error response header provides structured error information when signature verification fails. Together, these mechanisms enable flexible trust models ranging from privacy-preserving pseudonymous verification to horizontally-scalable delegated authentication and PKI-based identity chains.

.# Discussion Venues

*Note: This section is to be removed before publishing as an RFC.*

Source for this draft and an issue tracker can be found at https://github.com/dickhardt/signature-key.

{mainmatter}

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Introduction

HTTP Message Signatures [@!RFC9421] provides a powerful mechanism for creating and verifying digital signatures over HTTP messages. To verify a signature, the verifier needs the signer's public key. While RFC 9421 defines signature creation and verification procedures, it intentionally leaves key distribution to application protocols, recognizing that different deployments have different trust requirements.

Where the signer and verifier have no prior relationship, that gap is usually filled by out-of-band pre-registration or by an application-specific token. This document addresses the cases those two options do not cover.

**A verifier may have no prior relationship with the signer.** Pre-registration assumes the signer is known before the request. Agents, first-contact clients, and cross-domain callers frequently are not. When the first request is also the first contact, there is no registration step in which to have exchanged a key. The key, or a means to obtain it, has to travel with the request.

**The key material and its trust model are separate questions.** "Which key signed this" and "why should the verifier trust that key" are distinct. A raw inline key answers the first and defers the second to the verifier's policy. A key discovered from an origin ties the key to that origin. A delegated key carries an assertion from a third party. A certificate chain carries a PKI trust path. These are different trust models over the same signature primitive, and a mechanism that hard-codes one of them cannot serve the others. This document treats the trust model as a scheme dimension rather than a fixed choice.

**Key conveyance must be covered by the signature it introduces.** If the keying material or its identifier travels alongside the signature but is not itself signed over, an intermediary can substitute a different key or identifier and the signature still verifies against the substituted key. Conveying the key in a covered component closes this. A design that carries the key outside the signature's covered components reopens it. (#signature-key-integrity) describes the scheme-substitution and identity-substitution attacks this prevents.

**The verifier must be able to state what it will accept.** A signer that guesses the wrong key distribution scheme, or the wrong algorithm, learns nothing useful from a bare verification failure. Without a way for the verifier to say what it requires and what it supports, the extension point cannot be exercised or negotiated, and it ossifies.

This document defines:

- **Signature-Key** ((#signature-key-http-request-header)) — a request header that distributes public keys for HTTP Message Signature verification. The header supports seven schemes, each designed for different trust models and operational requirements:

  1. **Header Web Key (hwk)** - Self-contained public keys for pseudonymous verification
  2. **JKT JWT (jkt-jwt)** - Self-issued key delegation via JWK Thumbprint JWTs ("jacket jot")
  3. **JWKS URI (jwks_uri)** - Identified signers with key discovery via metadata
  4. **Direct JWKS (jwks)** - Keys fetched directly from an HTTPS URL that is also the signer identity
  5. **JWT (jwt)** - Delegated keys embedded in signed JWTs for horizontal scale
  6. **Self-Issued JWT (self-jwt)** - Self-signed JWTs where the signer and issuer are the same party
  7. **X.509 (x509)** - Certificate-based verification with PKI trust chains

  Additional schemes may be defined through the IANA registry established by this document.

- **Accept-Signature-Scheme** and **Accept-Signature-Alg** ((#accept-signature-scheme-and-accept-signature-alg-response-headers)) — response headers stating the Signature-Key schemes and the signature algorithms the server accepts. Both are Lists, so a server states its full accepted set and a client selects a scheme and an algorithm before signing.

- **Signature-Error** ((#signature-error-http-response-header)) — a response header that provides structured error information when signature verification fails, enabling clients to diagnose and correct signing issues.

Three properties follow from the gaps above and are held as invariants throughout this document:

1. Keying material or its identifier is conveyed in the Signature-Key header, which is a covered component ((#signature-key-integrity)). The signature protects the key or identifier that introduces it.

2. The trust model is a scheme, not a fixed choice. A single header ((#signature-key-http-request-header)) carries any of an inline key, an origin-discovered key, a delegated key, or a certificate chain, distinguished by a scheme token. The header is one namespace for key conveyance; the trust model varies within it.

3. Unknown schemes and algorithms have defined, mandatory feedback. A verifier that does not implement a presented scheme returns `unsupported_scheme` with the set it supports ((#unsupported-scheme)). The extension point is exercised on ordinary traffic rather than only at the moment a new value is first deployed, per the guidance of [@?RFC9170].

The Signature-Key header works in conjunction with the Signature-Input and Signature headers defined in RFC 9421, using matching labels to correlate signature metadata with keying material.

The mechanisms in this document were designed as general-purpose building blocks and are used by other specifications. In the AAuth protocol [@?I-D.hardt-oauth-aauth-protocol], all parties communicate using Signature-Key to distribute the keys that verify their signed requests. Email Verification [@?I-D.hardt-email-verification] uses the `hwk` scheme to convey the browser's public key so the issuer can bind it into the verification token it issues. Additional protocols can adopt these mechanisms without further coordination.

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

**Unknown schemes:**

A verifier that encounters a scheme token it does not implement, including any unregistered value, MUST reject the request with a `Signature-Error` of `error=unsupported_scheme` ((#unsupported-scheme)) and MUST NOT fail in a scheme-specific or undefined manner. Verifiers SHOULD dispatch on the scheme token through a lookup over the HTTP Signature-Key Scheme registry ((#scheme-registry)) rather than a fixed set of branches, so that unknown schemes take this defined path.

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

## Multiple Signatures {#multiple-signatures}

The dictionary format supports multiple signatures per message. Each signature has its own dictionary member keyed by its unique label:

```
Signature-Input: sig1=(... "signature-key"), sig2=(... "signature-key")
Signature: sig1=:...:, sig2=:...:
Signature-Key: sig1=jwt;jwt="eyJ...", sig2=jwks_uri;id="https://example.com";dwk="eg-config";kid="k1"
```

Most deployments SHOULD use a single signature. When multiple signatures are required, the complete Signature-Key header (containing all keys) MUST be populated before any signature is created, and each signature MUST cover `signature-key`. This ensures all signatures protect the integrity of all key material. See (#signature-key-integrity) in Security Considerations. Alternative key distribution mechanisms outside this specification may be used for scenarios requiring independent signature addition.

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

## JKT JWT Self-Issued Key Delegation (jkt-jwt) {#jkt-jwt-scheme}

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

The stable (enclave) key algorithm in the JWT `alg` header is determined by what the enclave hardware supports. This document's example uses `ES256` with a P-256 stable key delegating to an Ed25519 request key; deployments whose enclaves support Ed25519 (or other) stable-key algorithms SHOULD document this explicitly. The `cnf.jwk` request key algorithm is likewise enclave-determined.

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

## JWKS URI Discovery (jwks_uri) {#jwks-uri-scheme}

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

## Direct JWKS (jwks) {#jwks-scheme}

The jwks scheme identifies the signer by an HTTPS URL that returns a JWKS directly. Unlike jwks_uri, there is no metadata document and no discovery hop: the URL is both the signer's identifier and the location of its keys.

**Parameters:**

- `url` (REQUIRED, String) - HTTPS URL of the signer's JWKS

- `kid` (REQUIRED, String) - Key identifier

**Discovery procedure:**

1. Apply egress admission ((#scheme-specific-risks)) to `url`

2. Fetch `url`

3. Parse as a JWKS ([@!RFC7517])

4. Find the key with matching `kid`

**Example:**

```
Signature-Key: sig=jwks;url="https://client.example/keys.jwks";kid="key-1"
```

**Identifier semantics:**

Under the jwks scheme the signer's identity is the JWKS URL itself. A verifier that allowlists or policies by identity is doing so against `url`. Because identity and key location are the same string, moving the JWKS to a different URL changes the signer's identity. Signers that need identity to remain stable while key location changes independently should use the jwks_uri scheme ((#jwks-uri-scheme)), whose indirection exists for that purpose (see (#why-jwks-uri)). The jwks scheme trades that decoupling for a single fetch and zero configuration.

**Use cases:**

- Signers that want a self-describing identifier with no metadata to host

- Deployments where the JWKS URL is an acceptable stable identity

- Single-hop verification where discovery indirection is unnecessary

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

## Self-Issued JWT (self-jwt)

The self-jwt scheme carries a signed JWT where the JWT issuer and the HTTP request signer are the same party. The signing key is discoverable from the issuer's JWKS, and that same key verifies both the JWT and the HTTP Message Signature. Unlike the jwt scheme, no `cnf` claim is present — the signing key is the confirmation key.

**Parameters:**

- `jwt` (REQUIRED, String) - Compact-serialized JWT

**JWT requirements:**

- MUST contain `iss` claim (HTTPS URL of the issuer)

- MUST contain `dwk` claim (dot well-known metadata document name) — the verifier constructs `{iss}/.well-known/{dwk}` to discover the issuer's `jwks_uri`

- MUST have `kid` in the JWT header identifying the signing key in the issuer's JWKS

- MUST NOT contain `cnf` claim

- SHOULD contain standard claims: `sub`, `aud`, `exp`, `iat`

- Verifiers SHOULD verify the JWT `typ` header parameter has an expected value per deployment policy, to optimize for a quick rejection

> **Note:** The mechanism by which the JWT is obtained is out of scope of this specification.

**Verification procedure:**

1. Parse the JWT parameter value per [@!RFC7519] Section 7.2. Verifiers SHOULD reject if the value is not a well-formed JWT. This and subsequent pre-signature checks allow the verifier to fail early without expensive cryptographic operations or network fetches.

2. Verify the JWT `typ` header parameter has an expected value per policy. Reject if unexpected.

3. Validate `exp` claim if present. Reject if the token has expired.

4. Verify `iss`, `dwk` claims and `kid` JWT header parameter are present. Reject if any is absent.

5. Verify `cnf` claim is absent. Reject if present.

6. Construct `{iss}/.well-known/{dwk}`, parse as JSON metadata, extract `jwks_uri`. Fetch JWKS from `jwks_uri`, find the key matching `kid` from the JWT header. Reject if the key is not found (error: `unknown_key`).

7. Verify JWT signature using the discovered key.

8. Validate remaining JWT claims per policy (`sub`, `aud`, etc.)

9. Verify HTTP Message Signature using the same key from step 6.

**Example:**

```
Signature-Key: sig=self-jwt;jwt="eyJhbGciOiJFUzI1NiIsImtpZCI6InIxIn0..."
```

JWT header:

```json
{
  "alg": "ES256",
  "kid": "r1",
  "typ": "aauth-resource+jwt"
}
```

JWT payload:

```json
{
  "iss": "https://resource.example",
  "dwk": "aauth-resource",
  "aud": "https://agent.example",
  "eid": "evt-abc123",
  "exp": 1732210000
}
```

The verifier fetches `https://resource.example/.well-known/aauth-resource`, retrieves the JWKS, finds the key with `kid="r1"`, verifies the JWT signature with it, then uses that same key to verify the HTTP Message Signature.

**Use cases:**

- Resources delivering events with application-layer claims that the verifier needs alongside key verification

- Clients presenting themselves directly without delegating to a separate authority

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

# Accept-Signature-Scheme and Accept-Signature-Alg Response Headers {#accept-signature-scheme-and-accept-signature-alg-response-headers}

[@!RFC9421] Section 5 defines the `Accept-Signature` response header for requesting HTTP Message Signatures. Its signature metadata parameters are Item parameters, whose values are bare Items ([@!RFC8941], Section 3.1.2) and cannot be lists. A server therefore cannot use `Accept-Signature` to state that it accepts any of several Signature-Key schemes, nor any of several algorithms: its `alg` parameter names one algorithm.

This document defines two response header fields that carry those sets. Both are List Structured Fields ([@!RFC8941], Section 3.1) of Tokens, so a server states everything it accepts in one response, and a client selects a scheme and an algorithm before it signs rather than discovering them through a rejection.

Both headers are advisory capability statements, not directives. A server that omits them is not asserting that it accepts everything; a client that cannot satisfy them learns the outcome from `Signature-Error` ((#error-codes)) as before.

## Accept-Signature-Scheme {#accept-signature-scheme}

`Accept-Signature-Scheme` is a List ([@!RFC8941], Section 3.1) of Tokens, each naming a scheme registered in the HTTP Signature-Key Scheme registry ((#scheme-registry)). It states the Signature-Key schemes the server accepts.

```http
Accept-Signature-Scheme: hwk, jwks_uri, jwt
```

Order is significant: a server SHOULD list schemes in descending order of preference, and a client SHOULD choose the earliest listed scheme it can satisfy. A client MUST NOT treat the order as a requirement; any listed scheme is acceptable.

A client MUST ignore tokens it does not recognize, so that a server may list schemes registered after the client was written without breaking it. A client that recognizes no listed scheme SHOULD NOT sign the request, since no scheme it can produce will be accepted.

## Accept-Signature-Alg {#accept-signature-alg}

`Accept-Signature-Alg` is a List ([@!RFC8941], Section 3.1) of Tokens, each an identifier from the HTTP Signature Algorithms registry ([@!RFC9421], Section 6.2). It states the signature algorithms the server accepts.

```http
Accept-Signature-Alg: ed25519, ecdsa-p256-sha256
```

Order, unknown-token handling, and the no-recognized-value case are as for `Accept-Signature-Scheme`.

`Accept-Signature-Alg` states what the server accepts. The `alg` parameter of `Accept-Signature` ([@!RFC9421], Section 5.1) requests one specific algorithm for a specific signature label. Where both are present, `alg` is the more specific instruction and the client SHOULD honor it; `alg` SHOULD name a member of `Accept-Signature-Alg`.

## Relationship to Accept-Signature

`Accept-Signature` continues to carry what is to be signed: the covered components, and the per-label parameters of [@!RFC9421] Section 5.1. The two headers defined here carry what the server will accept in the `Signature-Key` header and in the signature itself. They are independent fields; a response MAY include any combination.

Neither header is keyed by signature label. Both state a server-wide capability, which does not vary per signature. A deployment that genuinely requires different schemes for different labels in one multi-signature message is outside what these headers express, and states the requirement in its own protocol.

```http
HTTP/1.1 401 Unauthorized
Accept-Signature: sig1=("@method" "@path" "@authority");created
Accept-Signature-Scheme: jwks_uri, jwt
Accept-Signature-Alg: ed25519
```

The client responds with matching labels:

```
Signature-Key: sig1=jwks_uri;id="https://client.example";dwk="example-configuration";kid="key-1"
Signature-Input: sig1=("@method" "@path" "@authority" "signature-key");
    created=1732210000
Signature: sig1=:MEQCIA5...:
```

The `signature-key` covered component is added by the client per this specification's requirement that `signature-key` appear in covered components. The server does not need to list it in `Accept-Signature`.

## Sending on Errors and on Challenges

Both headers MAY be sent on any response. They are useful on two occasions in particular.

On a challenge, before the client has signed anything, they let the client choose correctly the first time.

On a `Signature-Error` response, they say what would have worked. A server returning `unsupported_scheme` ((#unsupported-scheme)) SHOULD include `Accept-Signature-Scheme`, and a server returning `unsupported_algorithm` ((#unsupported_algorithm)) SHOULD include `Accept-Signature-Alg`. The error names what went wrong; the header names what would succeed.

```http
HTTP/1.1 401 Unauthorized
Signature-Error: error=unsupported_scheme
Accept-Signature-Scheme: jwks_uri, jwt
```

## Response Status Codes

These headers can be set on any response. Below is a list of what they MAY mean on responses with the following status codes:

| Status | Meaning | Legacy client behavior | Signature-aware client behavior |
|--------|---------|----------------------|-------------------------------|
| `401` | Authentication required | Falls back to WWW-Authenticate | Signs request with an accepted Signature-Key scheme |
| `402` | Payment + authentication required | Processes payment mechanism | Signs request AND processes payment |
| `429` | Rate limited | Respects Retry-After, slows down | Signs request, gets higher per-key rate limit |

The `429` case is particularly important for incremental adoption: a server can add these headers to its existing 429 responses with zero risk. Legacy clients ignore the unknown header fields and respect `Retry-After`. Signature-aware clients sign with a pseudonymous key, giving the server a stable key thumbprint for per-client rate limiting, and the client gets a higher rate limit in return.

## Incremental Adoption

These headers are designed for zero-coordination deployment. They are unknown to legacy clients, and an unknown header field is ignored, so servers can add them to existing responses without breaking anything.

**Stage 1 - Rate limiting (429):** A server adds `Accept-Signature-Scheme: hwk` to its 429 responses. Legacy clients slow down as before. Signature-aware clients sign requests and get higher per-key rate limits. The server gains per-client rate limiting without requiring registration or API keys.

**Stage 2 - Authentication (401):** The server starts requiring signatures on some paths, returning 401 with `Accept-Signature-Scheme: hwk`. It can include `WWW-Authenticate` alongside for legacy clients that have other auth mechanisms. Signature-aware clients sign; legacy clients fall back to bearer tokens or other schemes.

**Stage 3 - Identity (401):** The server advertises `Accept-Signature-Scheme: jwks_uri, jwt, x509` on sensitive paths, requiring verifiable client identity. The server can now make identity-based policy decisions without pre-registration.

Each stage is independently deployable. A server can use stage 1 on all endpoints while using stage 3 on admin endpoints. No bilateral agreements or client coordination required.

## Coexistence with WWW-Authenticate

These headers and `WWW-Authenticate` ([@!RFC9110], Section 11.6.1) are independent header fields; a response MAY include both. A client that understands Signature-Key processes the `Accept-Signature-*` headers; a legacy client processes `WWW-Authenticate`. Neither header's presence invalidates the other.

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api"
Accept-Signature-Scheme: jwks_uri, jwt
Accept-Signature-Alg: ecdsa-p256-sha256
```

What a client that understands both mechanisms does depends on what the `WWW-Authenticate` auth-scheme does. Nothing on the wire says which, and this document defines no signal for it, but a client only faces the choice for a scheme it already understands.

- Where the challenge is an authentication or authorization challenge, such as `Basic` or `Bearer`, the two are alternatives. The client SHOULD sign the request rather than present the credential: a signature demonstrates possession of a private key over this request, whereas a bearer credential authenticates whoever holds it, and signing puts no credential on the wire that the exchange did not require. A response carrying both does not assert that the two grant the same access, so a client that needs what only the credential grants MAY present it instead, and a server that is not satisfied by the choice challenges again.

- Where the challenge is not an authentication or authorization challenge, such as the payment challenge defined by the Micropayment Protocol ([@?I-D.ryan-httpauth-payment]), the two are complements: satisfying one does not satisfy the other, and a client that wants the resource satisfies both.

A `402` response MAY include a payment mechanism such as x402 [@?x402] or the Micropayment Protocol ([@?I-D.ryan-httpauth-payment]) alongside a signature challenge. Payment is not authentication, so this is the complementary case and a client satisfies both:

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment id="x7Tg2pLq", method="example",
    request="eyJhbW91bnQiOiIxMDAw..."
Accept-Signature-Scheme: hwk
```

## Examples

Pseudonymous access:

```http
HTTP/1.1 401 Unauthorized
Accept-Signature-Scheme: hwk
```

Identity with algorithm restriction:

```http
HTTP/1.1 401 Unauthorized
Accept-Signature-Scheme: jwks_uri, jwt
Accept-Signature-Alg: ecdsa-p256-sha256
```

Rate limiting with pseudonymous upgrade:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 30
Accept-Signature-Scheme: hwk
```

Payment with pseudonymous authentication:

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment id="x7Tg2pLq", method="example",
    request="eyJhbW91bnQiOiIxMDAw..."
Accept-Signature-Scheme: hwk
```

## Client Processing {#client-processing}

When a client receives a response containing `Accept-Signature-Scheme` ((#accept-signature-scheme)), it MAY retry the request with an HTTP Message Signature using any listed Signature-Key scheme it can satisfy, preferring the earliest listed.

[@!RFC9421] Section 5.2 defines the processing of `Accept-Signature` by the client. A client MAY ignore `Accept-Signature-Scheme` and `Accept-Signature-Alg`, and MUST ignore tokens within them that it does not recognize.

If a client already knows which schemes and algorithms the server accepts (from a previous interaction or metadata), it MAY sign the initial request directly without waiting for a challenge response.

A conforming verifier, when presented with a well-formed request bearing an unknown or unregistered scheme, returns `unsupported_scheme` and an `Accept-Signature-Scheme` header naming what it accepts. This exercises the unknown-scheme path as a matter of defined behavior.

When a `429` response includes both `Retry-After` and `Accept-Signature-Scheme`, the client MAY retry one time with a signed request without waiting for the `Retry-After` interval. Signing the request provides a key thumbprint that enables per-client rate limiting, which may result in a higher rate limit for the client.

A server MAY return a `429` response without `Accept-Signature-Scheme` to a signed request when it wants to rate-limit the client regardless of signing. In this case, the client MUST respect `Retry-After` as usual.

> **Open Issue:** Should this specification define a baseline HTTP Message Signatures profile (minimum covered components, timestamp requirements, verification steps), or is that always the responsibility of the protocol using these headers? See [GitHub issue #7](https://github.com/dickhardt/signature-key/issues/7).

# Signature-Error HTTP Response Header

When a server rejects a signed request due to a signature-related error, the response SHOULD include the `Signature-Error` header. The response status code is typically `400 Bad Request`, since the signature or keying material is malformed or invalid. A server MAY use `401 Unauthorized` for recoverable errors (e.g., `unsupported_algorithm`, `unsupported_scheme`, `invalid_input`) where the client can retry with corrected parameters.

## Header Structure

The `Signature-Error` header is a Dictionary ([@!RFC8941], Section 3.2) with the following member:

- `error` (REQUIRED): A Token ([@!RFC8941], Section 3.3.4) indicating the error code.

Additional members are defined per error code. Recipients MUST ignore unknown members.

```http
Signature-Error: error=unsupported_algorithm
```

The `Signature-Error` header is the authoritative source for machine-readable error information. The client MUST NOT depend on the response body for error handling.

## Response Body

Servers SHOULD use Problem Details [@!RFC9457] (`application/problem+json`) for the response body when returning `Signature-Error`. The `type` member SHOULD be a URN of the form `urn:ietf:params:sig-error:<error-code>`, where `<error-code>` matches the `error` value in the header.

```json
{
  "type": "urn:ietf:params:sig-error:unsupported_algorithm",
  "title": "Unsupported signature algorithm",
  "status": 400,
  "detail": "The server does not support rsa-v1_5-sha256"
}
```

Extension members in the Problem Details object MAY duplicate information from the `Signature-Error` header for convenience. When the header and body conflict, the header takes precedence.

## Access Denied

When the server successfully verifies the client's signature and identity but denies access based on policy (e.g., the client is not authorized for this resource), the server returns `403 Forbidden`. This is not a signature error — the authentication succeeded but authorization was denied. The response MUST NOT include an `Accept-Signature-Scheme` header or a `Signature-Error` header.

## Error Codes {#error-codes}

### unsupported_algorithm {#unsupported_algorithm}

The signing algorithm used by the client is not supported by the server.

The response SHOULD include an `Accept-Signature-Alg` header ((#accept-signature-alg)) naming the algorithms the server accepts.

```http
Signature-Error: error=unsupported_algorithm
Accept-Signature-Alg: ed25519, ecdsa-p256-sha256
```

### unsupported_scheme {#unsupported-scheme}

The Signature-Key scheme presented by the client is not supported by the server.

The response SHOULD include an `Accept-Signature-Scheme` header ((#accept-signature-scheme)) naming the schemes the server accepts.

```http
Signature-Error: error=unsupported_scheme
Accept-Signature-Scheme: jwks_uri, jwt
```

This error is recoverable. A server MAY return it with `401 Unauthorized` so the client can retry with an accepted scheme.

### invalid_signature

The HTTP Message Signature is missing, malformed, or cryptographic verification failed. This includes missing `Signature`, `Signature-Input`, or `Signature-Key` headers, an expired `created` timestamp, or a signature that does not verify.

```http
Signature-Error: error=invalid_signature
```

### invalid_input

The Signature-Input is missing required covered components.

- `required_input` (OPTIONAL): An Inner List of String ([@!RFC8941], Section 3.1.1) listing the covered components the server requires. The response SHOULD include this member.

```http
Signature-Error: error=invalid_input,
    required_input=("@method" "@authority" "@path"
    "signature-key" "content-digest")
```

### invalid_request

The request is malformed or missing required information unrelated to signature verification — such as missing query parameters or an unsupported content type.

```http
Signature-Error: error=invalid_request
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

# Security Considerations

## Key Validation

Verifiers MUST validate all cryptographic material before use:

- **hwk**: Validate JWK structure and key parameters per [@!RFC7517]

- **jwks_uri**: Verify HTTPS transport and validate fetched JWKS per [@!RFC7517]

- **jwks**: Verify HTTPS transport and validate fetched JWKS per [@!RFC7517]

- **x509**: Validate complete certificate chain per [@!RFC5280], check revocation status

- **jwt**: Verify JWT signature per [@!RFC7519] and validate embedded JWK per [@!RFC7517]

- **self-jwt**: Verify JWT signature per [@!RFC7519] using the key discovered from `{iss}/.well-known/{dwk}`; reuse that key as the HTTP signing key

- **jkt-jwt**: Verify JWT signature per [@!RFC7519] using header `jwk`, validate thumbprint matches `iss` per [@!RFC7638], validate embedded ephemeral JWK per [@!RFC7517]

## Caching and Performance

Verifiers MAY cache keys to improve performance but MUST implement appropriate cache expiration:

- **jwks_uri**: Respect cache-control headers, implement reasonable TTLs. Verifiers MUST NOT refetch a given issuer's JWKS more frequently than once per minute to prevent abuse.

- **jwks**: Cache by `url`; the same cache-control handling and once-per-minute refetch floor as `jwks_uri` apply.

- **x509**: Cache by `x5t`, invalidate on certificate expiry

- **jwt**: Cache embedded keys until JWT expiration

- **self-jwt**: Cache discovered keys until JWT expiration; cache by `iss` + `kid`

- **jkt-jwt**: Cache embedded keys until JWT expiration; cache by `iss` thumbprint URI

Verifiers SHOULD implement cache limits to prevent resource exhaustion attacks.

When the `Signature-Key` scheme is `jwks_uri` and a cached key matching the JWT `kid` fails signature verification, the verifier SHOULD refresh the issuer's JWKS once and retry verification before returning `unknown_key` (if the key is then absent) or `invalid_jwt` (if verification still fails), subject to the once-per-minute fetch floor and egress admission ((#scheme-specific-risks)) that apply to unknown-`kid` refreshes. This covers silent re-keying where the issuer replaces key material under the same `kid` without changing the identifier.

## Scheme-Specific Risks {#scheme-specific-risks}

**hwk**: No identity verification - suitable only for scenarios where pseudonymous access is acceptable.

**jkt-jwt**: The security of this scheme depends on the enclave key's private key remaining protected in hardware. If the enclave key is compromised, all delegated ephemeral keys are compromised. Verifiers should be aware that the jkt-jwt scheme implies but does not prove hardware protection — there is no attestation mechanism in this scheme. Unlike the `jwt` scheme where trust is rooted in a discoverable issuer, jkt-jwt trust is rooted in the key itself. Verifiers MUST understand that any party can create a jkt-jwt — the scheme provides pseudonymous identity, not verified identity. The `exp` claim on the JWT controls how long the ephemeral key is valid. Shorter lifetimes limit the exposure window if an ephemeral key is compromised. Implementations SHOULD use the shortest practical lifetime. The `iss` value is a JWK Thumbprint URI — a globally unique, collision-resistant identifier. The verifier MUST always compute the expected `iss` from the header `jwk` and compare by string equality — never trust the `iss` value alone.

**jwks_uri**: Relies on HTTPS security — vulnerable to DNS/CA compromise. Beyond HTTPS validation, nothing prevents an attacker from copying a client's public keys and serving them from a different domain. Verifiers SHOULD verify that the `id` parameter in the Signature-Key header matches an expected or authorized origin.

Because the JWKS location (and, for `jwks_uri`, the metadata document that yields it) is controlled by the asserted signer, an unconstrained verifier can be induced to fetch attacker-chosen internal URLs (SSRF). Verifiers MUST apply egress admission before fetching issuer metadata, a `jwks_uri`, or a `jwks` `url`:

- Require HTTPS for all outbound fetches.
- Enforce response-size and timeout limits.
- Refuse or constrain redirects (at minimum, do not follow redirects to a different host).
- Reject private, loopback, and link-local destination addresses unless explicitly allowed by deployment configuration.
- Defend against DNS rebinding by pinning the resolved IP address for the duration of the connection.
- Treat cross-origin `jwks_uri` URLs (where the JWKS host differs from the metadata host) as requiring explicit deployment admission.

**jwks**: The jwks scheme carries the same server-side request forgery exposure as jwks_uri, and arguably more directly, since the verifier fetches a client-supplied URL with no metadata step to anchor it. The egress-admission requirements above apply to jwks without exception. Because the signer's identity is the JWKS URL itself, a verifier that policies by identity is policying against a value the presenter chooses; verifiers SHOULD verify that `url` matches an expected or authorized origin.

**jwt**: Delegation trust depends on JWT issuer verification. Verifiers MUST validate JWT signatures and claims before trusting embedded keys.

**self-jwt**: Trust is rooted entirely in the issuer's JWKS. The same SSRF egress admission requirements that apply to `jwks_uri` and `jwt` apply here — the `iss` and `dwk` values are asserted by the presenter. Verifiers MUST validate that `cnf` is absent before treating the scheme as self-issued; a JWT containing `cnf` MUST be rejected. Short JWT lifetimes are especially important because the signing key also authenticates the HTTP request — compromise of the key is immediately exploitable at both layers.

**x509**: Requires robust certificate validation including revocation checking. Verifiers MUST NOT skip certificate chain validation.

## Algorithm Selection

The signature algorithm is determined by the key material in Signature-Key, not by the optional `alg` parameter in Signature-Input ([@!RFC9421], Section 2.3). For JWK-based schemes (hwk, jkt-jwt, jwks_uri, jwks, jwt, self-jwt), the algorithm is identified by the key type and curve (`kty` + `crv`) or by the `alg` parameter in the JWK ([@!RFC7517]). For the x509 scheme, the algorithm is determined by the certificate's public key type.

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

The jwks_uri, jwks, x509, jwt, and self-jwt schemes reveal signer identity. When a client presents its identity via these schemes, the server learns the client's HTTPS URL or certificate subject, revealing which software is making the request. Servers SHOULD NOT disclose client identity information to third parties without the client operator's consent.

## Key Discovery Tracking

The jwks_uri, jwks, jwt, self-jwt, and x509 schemes require verifiers to fetch resources from signer-controlled URLs. This creates tracking vectors:

- Signers can observe when and from where keys are fetched. In particular, when a server fetches a client's JWKS from `jwks_uri` at verification time, the fetch reveals to the JWKS host that someone is verifying signatures for that client.

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

Header field name: Signature-Error

Applicable protocol: http

Status: standard

Author/Change controller: IETF

Specification document(s): [this document]

Header field name: Accept-Signature-Scheme

Applicable protocol: http

Status: standard

Author/Change controller: IETF

Specification document(s): [this document]

Header field name: Accept-Signature-Alg

Applicable protocol: http

Status: standard

Author/Change controller: IETF

Specification document(s): [this document]

## Signature-Key Scheme Registry {#scheme-registry}

This document establishes the "HTTP Signature-Key Scheme" registry. This registry allows for the definition of additional key distribution schemes beyond those defined in this document.

### Registration Procedure

New scheme registrations require Specification Required per [@!RFC8126].

### Initial Registry Contents

| Scheme | Description | Reference |
|--------|-------------|-----------|
| hwk | Header Web Key - inline public key | [this document] |
| jkt-jwt | JKT JWT Self-Issued Key Delegation - enclave-backed delegation | [this document] |
| jwks_uri | JWKS URI Discovery - key discovery via metadata | [this document] |
| jwks | Direct JWKS - JWKS fetched directly from an HTTPS URL that is also the signer identity | [this document] |
| jwt | JWT Confirmation Key - delegated key in JWT | [this document] |
| self-jwt | Self-Issued JWT - signer and issuer are the same party | [this document] |
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

## URN Sub-namespace Registration

This document registers the following URN sub-namespace in the "IETF URN Sub-namespace for Registered Protocol Parameter Identifiers" registry defined in [@!RFC3553].

Registry name: sig-error

Specification: [this document]

Repository: [this document], Section on Error Codes

Index value: Values are registered in the "Signature Error Code" registry defined in this document.

The URN pattern is `urn:ietf:params:sig-error:<error-code>`, where `<error-code>` corresponds to a value in the Signature Error Code registry. These URNs are used as Problem Details `type` values ([@!RFC9457]) in response bodies accompanying `Signature-Error` headers.

## Signature Error Code Registry

This document establishes the "Signature Error Code" registry. New values may be registered following the Specification Required policy ([@!RFC8126]).

### Initial Registry Contents

| Value | Description | Reference |
|-------|-------------|-----------|
| `unsupported_algorithm` | Signing algorithm not supported | [this document] |
| `unsupported_scheme` | Signature-Key scheme not supported | [this document] |
| `invalid_signature` | Signature missing, malformed, or verification failed | [this document] |
| `invalid_input` | Missing required covered components | [this document] |
| `invalid_request` | Missing required info unrelated to signature | [this document] |
| `invalid_key` | Key cannot be parsed or doesn't meet trust requirements | [this document] |
| `unknown_key` | Key not found at jwks_uri | [this document] |
| `invalid_jwt` | JWT malformed or signature verification failed | [this document] |
| `expired_jwt` | JWT expired | [this document] |

# Document History

*Note: This section is to be removed before publishing as an RFC.*

- draft-hardt-httpbis-signature-key-07

  Not backward compatible with -06. Breaking changes are listed first.

  Breaking changes:

  - Removed the `sigkey` Accept-Signature parameter and its registry entry. A parameter value is a bare Item and cannot be a list, so `sigkey` could name only one scheme. Use `Accept-Signature-Scheme` and `Accept-Signature-Alg`, which are Lists of Tokens and let a client select before it signs rather than after a rejection.
  - Removed the `supported_algorithms` member of `Signature-Error`, added in -04. Use `Accept-Signature-Alg`, which works on a challenge and on an error alike.

  Other changes:

  - Added the `jwks` scheme: a direct JWKS fetch whose HTTPS `url` is both the signer identity and the key location, under the same egress-admission rules as `jwks_uri`.
  - Added the `unsupported_scheme` error code and made unknown-scheme rejection mandatory and conformance-testable.
  - Specified client behaviour when a response carries both `WWW-Authenticate` and a signature challenge: alternatives where the auth-scheme authenticates, in which case the client signs rather than presenting the credential, and complements where it does not, such as a payment challenge, in which case the client satisfies both. Addresses issue #17.
  - Expanded the Introduction to state the gaps this document addresses and the invariants that follow.
  - Added rationale for a scheme token rather than a header per scheme, for carrying the accepted sets in header fields rather than in parameters or error members, and for not reserving grease values.
  - Corrected the Accept-Signature parameter name from `algs` to `alg`, per [@!RFC9421], Section 5.1.
  - Converted internal cross-references to mmark xref syntax so they render as section numbers.

- draft-hardt-httpbis-signature-key-06
  - Added the `self-jwt` scheme for self-issued JWTs where the signer and the JWT issuer are the same party. The JWT signing key, discovered via `{iss}/.well-known/{dwk}`, is reused as the HTTP signing key, and no `cnf` claim is present.

- draft-hardt-httpbis-signature-key-05
  - Incorporated implementer feedback from Joshua Gay (sidecat), and added him to the acknowledgments.
  - Added a mandatory egress-admission checklist to the `jwks_uri` SSRF risk bullet: HTTPS, size and timeout limits, redirect policy, private and loopback address rejection, DNS rebinding defense, and cross-origin JWKS admission.
  - Added a once-per-minute JWKS fetch floor, and a same-`kid` refresh rule allowing one refresh and retry before returning `unknown_key` or `invalid_jwt`, subject to that floor and to egress-admission policy.
  - Noted that the stable (enclave) key algorithm in `jkt-jwt` is enclave-determined, and that deployments supporting Ed25519 or other stable-key algorithms SHOULD document this.

- draft-hardt-httpbis-signature-key-04
  - Renamed the specification from "HTTP Signature-Key Header" to "HTTP Signature Keys".
  - Added the `sigkey` parameter to Accept-Signature ([@!RFC9421], Section 5) with three values: `jkt` (pseudonymous), `uri` (URI-identified), and `x509` (PKI certificate), and registered it in the HTTP Signature Metadata Parameters registry.
  - Added the Signature-Error response header and established the Signature Error Code registry.
  - Added an incremental adoption section describing zero-coordination deployment via 429, 401, and 402 responses.
  - Added privacy considerations for key thumbprint tracking, agent identity disclosure, and the JWKS fetch side channel.

- draft-hardt-httpbis-signature-key-03
  - Added the `jkt-jwt` scheme for self-issued key delegation, with a TOFU reference to [@?RFC7435].
  - Renamed the `well-known` parameter to `dwk` (dot well-known).
  - Added `iss` and `dwk` claims to the jwt scheme (SHOULD) for issuer key discovery.
  - Added an early validation step to jwt verification: format, `typ`, and `exp` checks before any network fetch.
  - Added design rationale for `jwks_uri` rather than an inline JWKS, and moved the hwk string versus byte sequence note to the rationale appendix.
  - Reordered the schemes and added acknowledgments.

- draft-hardt-httpbis-signature-key-02
  - Changed the `x5t` parameter to a byte sequence, per reviewer feedback.
  - Added structured field types to all parameters.
  - Added a design note on the string versus byte sequence choice for hwk.

- draft-hardt-httpbis-signature-key-01
  - Initial public draft, with four schemes: hwk, jwks_uri, x509, and jwt.

# Acknowledgments

The author would like to thank Joshua Gay and Yaron Sheffer for their feedback on this specification.

{backmatter}

# Design Rationale

## Why jwks_uri Instead of Inline JWKS? {#why-jwks-uri}

The `jwks_uri` and `jwt` schemes reference a `jwks_uri` property in the `.well-known` metadata document rather than embedding the JWKS directly in the metadata. This separation of concerns is deliberate:

1. **Independent key rotation**: Keys can be rotated by updating the JWKS endpoint without modifying the `.well-known` metadata document. This decouples key lifecycle management from configuration management, allowing operations teams to rotate keys on their own schedule without redeploying metadata.

2. **Independent management**: The `.well-known` metadata document and the JWKS can be hosted, managed, and secured by different systems or teams. For example, an identity team may manage keys while a platform team manages service metadata.

3. **Caching semantics**: The JWKS endpoint can have its own cache-control headers tuned for key rotation frequency (e.g., short TTLs during a rotation event), independent of the `.well-known` document's caching policy.

4. **Consistency with existing standards**: This approach mirrors the pattern established by OpenID Connect Discovery [@?OpenID.Discovery] and OAuth Authorization Server Metadata [@?RFC8414], which both use `jwks_uri` in metadata documents for the same reasons.

## Why Both jwks and jwks_uri?

The `jwks` and `jwks_uri` schemes occupy adjacent points on a simplicity/decoupling axis. `jwks_uri` fetches a `.well-known` metadata document and follows its `jwks_uri` property to the keys, so identity (the `id` origin) is separate from key location (the discovered JWKS URL); the two can be managed and rotated independently, as (#why-jwks-uri) describes. `jwks` collapses this to a single HTTPS fetch whose URL is both identity and key location. Neither dominates: `jwks` removes a hop and all metadata hosting at the cost of tying identity to the JWKS URL, while `jwks_uri` keeps identity stable across key-location changes at the cost of a discovery step. Offering both lets a signer choose the tradeoff rather than having it imposed.

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

## Why a Scheme Token Instead of a Header per Scheme?

An alternative design would define a distinct header field per key distribution mechanism (for example `Signature-Key-Hwk`, `Signature-Key-Jwt`) rather than one `Signature-Key` header carrying a scheme token. HTTP field names are the most heavily exercised extension point on the web, and [@?RFC9170] identifies header fields in email and HTTP as the canonical case of an extension point that stays usable because recipients routinely ignore fields they do not understand. A per-mechanism header would ride that established tolerance rather than a scheme registry with little traffic. This document nonetheless uses a single header with a scheme token, for four reasons.

1. **Ignorability is the wrong property for keying material.** Header-name extensibility works because an unknown header can be safely ignored. `Signature-Key` carries mandatory keying material. A verifier that ignores an unknown `Signature-Key-X` header fails verification exactly as if no key were present, and cannot tell the client why. With a scheme token, the verifier knows a key was offered under a scheme it does not implement and returns `unsupported_scheme` with an `Accept-Signature-Scheme` header naming what it accepts. [@?RFC9170] Section 4.4 notes that effective feedback is what keeps the surrounding extension machinery working.

2. **The covered-component invariant stays fixed.** The scheme substitution and identity substitution attacks in (#signature-key-integrity) depend on `signature-key` being a covered component. With one header, `signature-key` is a single stable identifier in the signature base across every scheme. Per-scheme headers would make the covered component name mechanism-dependent and would require a rule for a request that covers one key header while leaving another uncovered.

3. **Label correlation stays simple.** The dictionary is keyed by signature label so that each signature in a multi-signature message carries its own keying material ((#multiple-signatures)). Resolving a label's key is one dictionary lookup. Across N per-scheme headers it becomes a scan with a cross-header collision policy.

4. **Fewer namespaces.** [@?RFC9170] Section 4.1 observes that a smaller number of widely applicable extension points is exercised more, and ossifies less, than many specialized ones. The scheme is the single namespace for key distribution mechanisms, referenced from both this header and the `Accept-Signature-Scheme` response header. Per-scheme header names would add a second namespace for the same axis.

To keep the scheme registry usable despite its narrow traffic, this document relies on defined behavior rather than on greasing [@?RFC8701]. Unknown and unregistered schemes have a single mandatory outcome ((#unsupported-scheme)), verifiers dispatch through the registry rather than a fixed branch set, and conformance testing exercises the unknown-scheme path directly ((#client-processing)). Reserving grease values was considered and not adopted: a mandatory, conformance-tested reject path exercises the same handling that grease would provoke, whereas a reserved grease token tends to become a filterable synonym for "unknown" that implementations special-case, the outcome [@?RFC9170] Section 3.3 cautions against.

## Why Accept-Signature-Scheme and Accept-Signature-Alg Are Separate Headers

Earlier versions of this document carried the server's scheme requirement in a `sigkey` parameter on `Accept-Signature`, and the accepted sets in `supported_schemes` and `supported_algorithms` members of `Signature-Error`. Both were replaced by two response header fields. The reasons are worth recording, because at first reading a new header field looks like the more invasive choice.

1. **A set cannot be expressed in a parameter.** A Structured Fields parameter value is a bare Item ([@!RFC8941], Section 3.1.2) and cannot be an Inner List. A parameter can therefore name one scheme, never a set. This is not a limitation of `sigkey`: the `alg` parameter of `Accept-Signature` ([@!RFC9421], Section 5.1) is singular for the same structural reason. Any design that puts the accepted set in a parameter slot is constrained to a single value, whatever it is named.

2. **The Accept-Signature member value is already spoken for.** The alternative to a parameter is a Dictionary member value, which may be an Inner List. In `Accept-Signature` that position holds the covered components, so it is unavailable. Carrying the accepted sets there would mean overloading one list with two unrelated kinds of token.

3. **Capability does not vary by signature label.** A new Dictionary keyed by label could carry a list per label, but the schemes and algorithms a verifier accepts are a property of the verifier, not of a particular signature in a particular message. Keying by label would invite the question of what a client should do when two labels disagree, and would create a per-label negotiation surface with no deployment behind it. `Accept-Signature` retains label granularity for what it is for: which components are to be covered, and the per-label parameters of [@!RFC9421] Section 5.1.

4. **One dimension per field is the established HTTP pattern.** HTTP negotiates with `Accept`, `Accept-Encoding`, `Accept-Language`, and `Accept-Charset`: one field per dimension, each a list, each independently ignorable. A single field carrying both dimensions as Dictionary members would be equally valid Structured Fields, but it would depart from that pattern, and it would couple the two: a server with no algorithm constraint could not simply omit the algorithm field.

5. **The same syntax serves the challenge and the error.** This is the property the previous design could not have. `supported_schemes` and `supported_algorithms` lived inside `Signature-Error`, so a client could reach them only by first being rejected. A header field can be sent on an ordinary challenge, before the client has signed anything, and on an error response, and means the same thing in both places. A client selects a scheme and an algorithm before it signs rather than after a failure. [@?RFC9170] Section 4.4 observes that an extension point stays usable when it is exercised routinely; a set that can be learned only through failure is exercised only when something goes wrong.

6. **Removing the error members avoids two ways to say one thing.** Once the headers exist, retaining the members would leave two encodings of the same information, differing only in when they may appear. [@?RFC9170] Section 4.1 notes that redundant, partially-used mechanisms ossify. `Signature-Error` now states what went wrong, and the `Accept-Signature-*` fields state what would succeed.

Adding header fields here does not contradict the argument against per-scheme key headers in (#why-a-scheme-token-instead-of-a-header-per-scheme). That argument turns on ignorability being the wrong property for mandatory keying material: a verifier that silently ignores an unknown `Signature-Key-X` cannot tell the client why verification failed. These fields carry advisory capability rather than keying material, and ignorability is exactly the property wanted. A client that does not understand `Accept-Signature-Scheme` ignores it and behaves as it did before, which is also what a client that cannot satisfy any listed scheme does. Nothing is lost by ignoring a hint, whereas ignoring a key is a silent failure. The two conclusions differ because the requirements differ.

## Why Strings Instead of Byte Sequences for hwk?

The hwk parameters use structured field strings rather than byte sequences. JWK key values are base64url-encoded per [@!RFC7517], while structured field byte sequences use base64 encoding per [@!RFC8941]. Using strings allows implementations to pass JWK values directly without converting between base64url and base64, avoiding a potential source of encoding bugs.

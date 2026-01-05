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

date = 2026-01-05T00:00:00Z

[[author]]
initials = "D."
surname = "Hardt"
fullname = "Dick Hardt"
organization = "Hellō"
  [author.address]
  email = "dick.hardt@gmail.com"

%%%

.# Abstract

This document defines the Signature-Key HTTP header field for distributing public keys used to verify HTTP Message Signatures as defined in RFC 9421. The header supports four key distribution schemes: pseudonymous inline keys (hwk), identified signers with JWKS discovery (jwks), X.509 certificate chains (x509), and JWT-based delegation (jwt). These schemes enable flexible trust models ranging from privacy-preserving anonymous verification to PKI-based identity chains and horizontally-scalable delegated authentication.

.# Discussion Venues

*Note: This section is to be removed before publishing as an RFC.*

Source for this draft and an issue tracker can be found at https://github.com/dickhardt/signature-key.

{mainmatter}

# Introduction

HTTP Message Signatures [@!RFC9421] defines a mechanism for creating and verifying signatures over HTTP messages. However, RFC 9421 does not specify how verifiers obtain the public keys needed to verify signatures. This creates an interoperability gap where different implementations must define custom key distribution mechanisms.

This document defines the Signature-Key HTTP header field to address this gap. The header provides four standardized schemes for key distribution, each suited to different trust models and operational requirements:

1. **Header Web Key (hwk)** - Self-contained public keys for pseudonymous verification
2. **JWKS (jwks)** - Identified signers with key discovery via HTTPS
3. **X.509 (x509)** - Certificate-based verification with PKI trust chains
4. **JWT (jwt)** - Delegated keys embedded in signed JWTs for horizontal scale

The Signature-Key header works in conjunction with the Signature-Input and Signature headers defined in RFC 9421, using matching labels to correlate signature metadata with keying material.

# The Signature-Key Header Field

The Signature-Key header field provides the public key or key reference needed to verify an HTTP Message Signature. The header is a Structured Field Dictionary [@!RFC8941] keyed by signature label, where each member describes how to obtain the verification key for the corresponding signature.

**Format:**

```
Signature-Key: <label>=<scheme>;<parameters>...
```

Where:
- `<label>` (dictionary key) matches the label in Signature-Input and Signature headers
- `<scheme>` (item value) is one of: hwk, jwks, x509, jwt
- `<parameters>` are semicolon-separated key-value pairs that vary by scheme

**Label Correlation:**

Labels are correlated by equality of label names across Signature-Input, Signature, and Signature-Key. Signature-Key is a dictionary keyed by label; Signature-Input and Signature are the sources of what signatures are present; Signature-Key provides keying material for those labels.

Verifiers MUST:
1. Parse Signature-Input and Signature per RFC 9421 and obtain the set of signature labels present. The verifier determines which labels it is attempting to verify based on application context and RFC 9421 processing.
2. Parse Signature-Key as a Structured Fields Dictionary
3. For each label being verified, select the Signature-Key dictionary member with the same name
4. If the corresponding dictionary member is missing, verification for that signature MUST fail

> **Note:** A verifier might choose to verify only a subset of labels present (e.g., the application-required signature); labels not verified can be ignored.

Profiles MAY define stricter label selection and mismatch handling rules.

**Example:**

```
Signature-Input: sig=("@method" "@path"); created=1732210000
Signature: sig=:MEQCIA5...
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="JrQLj..."
```

## Label Consistency

If a label appears in Signature or Signature-Input, and the verifier attempts to verify it, the corresponding member MUST exist in Signature-Key. If Signature-Key contains members for labels not being verified, verifiers MAY ignore them.

This section defines base correlation behavior; profiles MAY impose additional rejection conditions (e.g., exactly one label, no extra members).

## Profiles and Application Constraints

Signature-Key supports multiple signatures per RFC 9421 using a dictionary with multiple members. Application protocols (profiles) MAY constrain:

- Number of signatures
- Label constraints
- Verification rejection conditions

This document defines the base format and schemes only.

> **Note:** AAuth is a profile that requires exactly one signature and exactly one Signature-Key dictionary member. AAuth defines a single-signature profile and specifies stricter label selection and mismatch handling rules. AAuth uses Signature-Key's single dictionary member name as the expected label and requires the other signature headers to match it.

**Multiple Signatures:**

The dictionary format supports multiple signatures per message. Each signature has its own dictionary member keyed by its unique label:

```
Signature-Input: sig1=(...), sig2=(...)
Signature: sig1=:...:, sig2=:...:
Signature-Key: sig1=hwk;kty="OKP";x="...", sig2=jwt;jwt="eyJ..."
```

Profiles MAY require a single signature and define rejection behavior for multiple labels in Signature-Input/Signature or multiple members in Signature-Key. Those restrictions are profile-specific and not imposed by this document.

## Header Web Key (hwk)

The hwk scheme provides a self-contained public key inline in the header, enabling pseudonymous verification without key discovery.

**Parameters:**
- `kty` (REQUIRED) - Key type: "OKP", "EC", or "RSA"
- `crv` (REQUIRED for OKP/EC) - Curve name
- Key material (REQUIRED):
  - OKP/EC: `x` (and `y` for EC)
  - RSA: `n` and `e`

**Example:**

```
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
```

**Constraints:**
- The `alg` parameter MUST NOT be present (algorithm is specified in Signature-Input)
- The `kid` parameter SHOULD NOT be used

**Use cases:**
- Privacy-preserving agents that avoid identity disclosure
- Experimental or temporary access without registration
- Rate limiting and reputation building on a per-key basis

## JWKS Discovery (jwks)

The jwks scheme identifies the signer and enables key discovery via HTTPS URLs. It supports two modes: direct JWKS URL or identifier-based discovery with optional metadata.

**Parameters:**
- `kid` (REQUIRED) - Key identifier

**Mode 1: Direct JWKS URL**
- `jwks` (REQUIRED) - Direct HTTPS URL to JWKS document

**Mode 2: Identifier + Metadata**
- `id` (REQUIRED) - Signer identifier (HTTPS URL)
- `well-known` (OPTIONAL) - Metadata document name under `/.well-known/`

The `jwks` and `id` parameters MUST NOT both be present.

**Discovery procedure (Mode 1 - Direct JWKS):**
1. Fetch JWKS from the `jwks` URL
2. Find key with matching `kid`

**Discovery procedure (Mode 2 - Identifier + Metadata):**

If `well-known` parameter is present:
1. Fetch `{id}/.well-known/{well-known}`
2. Parse as JSON metadata
3. Extract `jwks_uri` property
4. Fetch JWKS from `jwks_uri`
5. Find key with matching `kid`

If `well-known` parameter is absent:
1. Fetch `{id}` directly as JWKS
2. Find key with matching `kid`

**Example (direct JWKS URL):**

```
Signature-Key: sig=jwks;jwks="https://agent.example/jwks.json";kid="key-1"
```

**Example (identifier - direct fetch):**

```
Signature-Key: sig=jwks;id="https://agent.example/crawler";kid="key-1"
```

**Example (identifier with metadata):**

```
Signature-Key: sig=jwks;id="https://agent.example";well-known="aauth-agent";kid="key-1"
```

**Use cases:**
- Identified services with stable HTTPS identity
- Search engine crawlers and monitoring services
- Services requiring explicit entity identification

## X.509 Certificates (x509)

The x509 scheme provides certificate-based verification using PKI trust chains.

**Parameters:**
- `x5u` (REQUIRED) - URL to X.509 certificate chain (PEM format, [@!RFC7517] Section 4.6)
- `x5t` (REQUIRED) - Certificate thumbprint: BASE64URL(SHA256(DER(leaf_cert)))

**Verification procedure:**

1. Check cache for certificate with matching `x5t`
2. If not cached or expired, fetch PEM from `x5u`
3. Validate certificate chain to trusted root CA
4. Check certificate validity and revocation status
5. Verify `x5t` matches leaf certificate
6. Extract public key from end-entity certificate
7. Verify signature using extracted key
8. Cache certificate indexed by `x5t`

**Example:**

```
Signature-Key: sig=x509;x5u="https://agent.example/.well-known/cert.pem";x5t="bWcoon4QTVn8Q6xiY0ekMD6L8bNLMkuDV2KtvsFc1nM"
```

**Use cases:**
- Enterprise environments with PKI infrastructure
- Integration with existing certificate management systems
- Scenarios requiring certificate revocation checking
- Regulated industries requiring certificate-based authentication

## JWT Confirmation Key (jwt)

The jwt scheme embeds a public key inside a signed JWT using the `cnf` (confirmation) claim [@!RFC7800], enabling delegation and horizontal scale.

**Parameters:**
- `jwt` (REQUIRED) - Compact-serialized JWT

**JWT requirements:**
- MUST contain `cnf.jwk` claim with embedded JWK
- SHOULD contain standard claims: `iss`, `sub`, `exp`, `iat`

**Verification procedure:**

1. Validate JWT signature using issuer's public key
2. Verify standard claims per policy (`iss`, `exp`, etc.)
3. Extract JWK from `cnf.jwk`
4. Verify HTTP Message Signature using extracted key

**Example:**

```
Signature-Key: sig=jwt;jwt="eyJhbGciOiJFUzI1NiI..."
```

**JWT payload example:**

```json
{
  "iss": "https://issuer.example",
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

# Security Considerations

## Key Validation

Verifiers MUST validate all cryptographic material before use:

- **hwk**: Validate JWK structure and key parameters
- **jwks**: Verify HTTPS transport and validate fetched JWKS
- **x509**: Validate complete certificate chain, check revocation status
- **jwt**: Verify JWT signature and validate embedded JWK

## Caching and Performance

Verifiers MAY cache keys to improve performance but MUST implement appropriate cache expiration:

- **jwks**: Respect cache-control headers, implement reasonable TTLs
- **x509**: Cache by `x5t`, invalidate on certificate expiry
- **jwt**: Cache embedded keys until JWT expiration

Verifiers SHOULD implement cache limits to prevent resource exhaustion attacks.

## Scheme-Specific Risks

**hwk**: No identity verification - suitable only for scenarios where pseudonymous access is acceptable.

**jwks**: Relies on HTTPS security - vulnerable to DNS/CA compromise. Verifiers should implement certificate pinning where appropriate.

**x509**: Requires robust certificate validation including revocation checking. Verifiers MUST NOT skip certificate chain validation.

**jwt**: Delegation trust depends on JWT issuer verification. Verifiers MUST validate JWT signatures and claims before trusting embedded keys.

## Algorithm Selection

The `alg` parameter in Signature-Input (RFC 9421) determines the signature algorithm. Verifiers MUST:

- Validate algorithm against policy (reject weak algorithms)
- Ensure key type matches algorithm requirements
- Reject algorithm/key mismatches

# Privacy Considerations

## Pseudonymity vs. Identity

The hwk scheme enables pseudonymous operation where the signer's identity is not disclosed. Verifiers should be aware that:

- hwk provides no identity linkage across requests (unless keys are reused)
- Key reuse enables tracking but may be necessary for reputation/rate-limiting
- Verifiers should not log or retain hwk keys beyond operational necessity

The jwks, x509, and jwt schemes all reveal signer identity. Protocols using these schemes should inform signers that their identity will be disclosed to verifiers.

## Key Discovery Tracking

The jwks and x509 schemes require verifiers to fetch resources from signer-controlled URLs. This creates potential tracking vectors:

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

{backmatter}

# Acknowledgments

The author would like to thank reviewers for their feedback on this specification.

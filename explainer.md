# Signature-Key Header Explainer

`Signature-Key` allows flexible, privacy-preserving, and interoperable key distribution for HTTP Message Signatures.

**Author:**  
Dick Hardt  
Hellō Identity  
Email: dick.hardt@hello.coop  
URI: https://github.com/DickHardt

**Date:** November 21, 2025
**Status:** Internet-Draft (Exploratory)

## TL;DR

`Signature-Key` solves key distribution for HTTP Message Signatures (RFC 9421):
- **sig=hwk** - Pseudonymous (inline key, no identity)
- **sig=jwks** - Identified (explicit identity with id + optional metadata)
- **sig=x509** - X.509 certificate (explicit identity via PKI trust chains)
- **sig=jwt** - Delegated (key inside signed JWT, enables horizontal scale)

**Why:** RFC 9421 defines how to sign HTTP messages but not how verifiers obtain the public key. Signature-Key provides four flexible schemes for different trust models.

---

## Overview
The `Signature-Key` HTTP header provides the keying material required to verify an HTTP Message Signature (RFC 9421).
It supports **four schemes** representing a natural progression from pseudonymous to identified to delegated access:

- `sig=hwk` — Header Web Key (pseudonymous, self-contained public key)
- `sig=jwks` — Identified signer (explicit identity with id, optional metadata discovery)
- `sig=x509` — X.509 certificate chain (explicit identity via PKI trust model)
- `sig=jwt` — JWT containing a `cnf.jwk` confirmation key (delegation and horizontal scale)

**Label matching:** The label (e.g., "sig") must be identical across `Signature-Input`, `Signature`, and `Signature-Key` headers for the same signature.

**Offline verification:** A verifier MAY pre-fetch, cache, or pin keys rather than performing key discovery as requests come in.

Example:

```http
Signature-Input:  sig=("@method" "@path"); created=1732210000
Signature:        sig=:MEQCIA5...
Signature-Key:    sig=hwk; kty="OKP"; crv="Ed25519"; x="JrQLj..."
```

---

## 1. `sig=hwk` — Header Web Key

`wk` provides a **self-contained**, **pseudonymous**, inline public key.  
No key lookup required.

### Example

```text
Signature-Key: sig=hwk;
    kty="OKP";
    crv="Ed25519";
    x="JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
```

### Required parameters
- `kty` — Key type (`OKP`, `EC`, `RSA`)
- `crv` — Curve (for OKP/EC)
- Key material:
  - OKP/EC: `x` (and `y` for EC)
  - RSA: `n` and `e`

### Forbidden / ignored
- `alg` MUST NOT appear
  (Algorithm is chosen from `Signature-Input.alg`)
- `kid` SHOULD NOT be used in `wk` mode

**When to use sig=hwk:**
- Privacy-preserving agents that don't want to reveal identity
- Experimental bots testing APIs without registration
- Abuse prevention through per-key rate limiting
- Building reputation before identifying yourself

---

## 2. `sig=jwks` — Identified Signer

`jwks` mode explicitly identifies the signer using `id` and retrieves key material from a JWKS document.

### Required parameters
- `id` — Signer identifier (HTTPS URL)
- `kid` — Key ID used for the HTTP Signature
- `well-known` — OPTIONAL name of metadata document under `/.well-known/`

> `well-known` could be shortened to `wk`

### Discovery

To discover the key, the verifier fetches:

- **If `well-known` is present:**
  Fetch `{id}/.well-known/{well-known}`, parse as metadata, extract `jwks_uri`, then fetch the JWKS

- **If `well-known` is absent:**
  Fetch `{id}` directly as a JWKS

The resulting JWKS **MUST** contain a key whose `kid` matches the `kid` parameter in the `Signature-Key` header.

### Examples

#### Direct JWKS fetch

```text
Signature-Key: sig=jwks;
    id="https://agent.example/crawler";
    kid="key-1"
```

Verifier fetches `https://agent.example/crawler` directly as a JWKS.

#### JWKS via metadata

```text
Signature-Key: sig=jwks;
    id="https://agent.example";
    well-known="agent-server";
    kid="key-1"
```

Verifier:
1. Fetches `https://agent.example/.well-known/agent-server`
2. Parses as JSON metadata
3. Extracts `jwks_uri` property
4. Fetches JWKS from the `jwks_uri` URL
5. Finds key with matching `kid`

**When to use sig=jwks:**
- Established services with stable HTTPS identity
- Search engine crawlers, monitoring services, security scanners
- Services operating from single authority with long-lived keys
- When explicit signer entity identification is required
- To satisfy identity requirements in Agent-Auth challenges

---

## 3. `sig=x509` — X.509 Certificate Chain

`x509` mode provides an X.509 certificate chain via URL, enabling PKI-based trust models.

### Required parameters
- `x5u` — URL to X.509 certificate chain in PEM format (RFC 7517 Section 4.6)
- `x5t` — Certificate thumbprint: BASE64URL(SHA256(DER_bytes_of_leaf_certificate))
  - Enables cache lookup and key rotation detection
  - Matches the `x5t#S256` parameter from RFC 7515 Section 4.1.8

### Example

```text
Signature-Key: sig=x509;
    x5u="https://agent.example/.well-known/cert.pem";
    x5t="bWcoon4QTVn8Q6xiY0ekMD6L8bNLMkuDV2KtvsFc1nM"
```

The verifier:
1. Check local cache for a certificate with matching `x5t` thumbprint
2. If cached certificate found and still valid, skip to step 5
3. Fetch the PEM file from the `x5u` URL
4. Parse and validate the X.509 certificate chain:
   - Verify chain of trust to a trusted root CA
   - Check certificate validity (not expired, not revoked via CRL/OCSP)
   - Validate certificate policies and constraints
   - Verify `x5t` matches BASE64URL(SHA256(DER_bytes_of_leaf_certificate))
5. Extract the public key from the end-entity certificate
6. Verify the HTTP Signature using the extracted public key
7. Cache the certificate indexed by `x5t` for future requests

**When to use sig=x509:**
- Enterprise environments with existing PKI infrastructure
- Integration with certificate management systems
- mTLS scenarios where certificates are already deployed
- When certificate-based trust chains and revocation are required
- Regulated industries requiring certificate-based authentication

**Benefits of x5t parameter:**
- **CDN caching**: CDNs can cache certificates by thumbprint without parsing the chain
- **Key rotation detection**: When keys at `x5u` change, the `x5t` changes, signaling fresh fetch needed
- **Performance**: Verifiers can check cache before fetching, reducing latency
- **Bandwidth**: Avoid re-fetching unchanged certificates on every request

**Security considerations:**
- Verifiers MUST validate the complete certificate chain
- Verifiers MUST check certificate revocation status (CRL or OCSP)
- Verifiers SHOULD enforce certificate policies appropriate to their security requirements
- The `x5u` URL MUST use HTTPS to prevent certificate substitution attacks

---

## 4. `sig=jwt` — JWT With Confirmation Key

`jwt` embeds a **JWK inside a signed JWT** using the standard `cnf` (confirmation) claim (RFC 7800).

This scheme enables **delegation and horizontal scale**: a central authority issues short-lived JWTs to distributed instances, each with their own ephemeral signing key.

### Example

```text
Signature-Key: sig=jwt;
    jwt="<compact-serialized-jwt>"
```

### Requirements
The JWT MUST contain a `cnf.jwk` claim:

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

### Verifier Procedure
1. Validate the JWT signature using the issuer's key
2. Verify standard claims: `iss`, `exp`, `iat` (per policy)
3. Extract the JWK from `cnf.jwk`
4. Verify the HTTP Message Signature using that key

**Use cases:**
- Agent tokens binding ephemeral keys to agent server identity
- Auth tokens binding agent key to authorization grant
- Distributed services where each instance has unique ephemeral keys


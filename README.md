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
- **sig=wk** - Pseudonymous (inline key, no identity)
- **sig=jwks** - Identified (fetch key from signer's HTTPS URL)
- **sig=jwt** - Delegated (key inside signed JWT, enables horizontal scale)

**Why:** RFC 9421 defines how to sign HTTP messages but not how verifiers obtain the public key. Signature-Key provides three flexible schemes for different trust models.

---

## Overview
The `Signature-Key` HTTP header provides the keying material required to verify an HTTP Message Signature (RFC 9421).
It supports **three schemes** representing a natural progression from pseudonymous to identified to delegated access:

- `sig=wk` — Inline Web Key (pseudonymous, self-contained public key)
- `sig=jwks` — Key discovery via signer identifier (identified service)
- `sig=jwt` — JWT containing a `cnf.jwk` confirmation key (delegation and horizontal scale)

**Label matching:** The label (e.g., "sig") must be identical across `Signature-Input`, `Signature`, and `Signature-Key` headers for the same signature.

Example:

```http
Signature-Input:  sig=("@method" "@path"); created=1732210000
Signature:        sig=:MEQCIA5...
Signature-Key:    sig=wk; kty="OKP"; crv="Ed25519"; x="JrQLj..."
```

---

## 1. `sig=wk` — Inline Web Key

`wk` provides a **self-contained**, **pseudonymous**, inline public key.  
No key lookup required.

### Example

```text
Signature-Key: sig=wk;
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

**When to use sig=wk:**
- Privacy-preserving agents that don't want to reveal identity
- Experimental bots testing APIs without registration
- Abuse prevention through per-key rate limiting
- Building reputation before identifying yourself

---

## 2. `sig=jwks` — Key Discovery via Signer Identifier

`jwks` mode identifies the signer using `id` and retrieves key material from a JWKS document.

### Required parameters
- `id` — Signer identifier (URI)
- `kid` — Key ID used for the HTTP Signature  
- `well-known` — OPTIONAL name of metadata under `/.well-known/`



To discover the key, the verifier fetches:

- If `well-known` is **present**:  
  Fetch:
  ```text
  {id}/.well-known/{well-known}
  ```

- If `well-known` is **absent**:  
  Fetch:
  ```text
  {id}
  ```

The response at that URI MUST be a JSON document that contains **either**:

1. `jwks` — an inline JWKS object, **or**  
2. `jwks_uri` — a URI pointing to a JWKS resource

If the JSON document contains `jwks_uri`, the verifier MUST fetch that URI to obtain the JWKS.

The resulting JWKS **MUST** contain a key whose `kid` matches the `kid` parameter in the `Signature-Key` header.

### Example

#### JWKS via `.well-known`

```text
Signature-Key: sig=jwks;
    id="https://issuer.example";
    well-known="openid-configuration";
    kid="abc123"
```

Fetch:

```text
https://issuer.example/.well-known/openid-configuration
```

That returns:

```json
{
    "iss":"https://issuer.example",
    "jwks_uri":"https://issuer.example/openid/jwks.json"
    ...
}

```

The verifier then fetches: 

```text
https://issuer.example/openid/jwks.json
```

That returns:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "abc123",
      "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
      "use": "sig"
    }
  ]
}
```

**When to use sig=jwks:**
- Established services with stable HTTPS identity
- Search engine crawlers, monitoring services, security scanners
- Services operating from single authority with long-lived keys
- When direct key publication is preferred over delegation

---

## 3. `sig=jwt` — JWT With Confirmation Key

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


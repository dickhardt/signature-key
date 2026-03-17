## JKT JWT (jkt-jwt)

The jkt-jwt scheme provides self-issued key delegation using a JWT whose signing key is embedded in the JWT header. This enables devices with hardware-backed secure enclaves to delegate signing authority to ephemeral keys, avoiding the performance cost of repeated enclave operations while maintaining a cryptographic chain of trust rooted in the enclave key.

### Motivation

Many devices — mobile phones, laptops, IoT hardware — include secure enclaves or trusted execution environments (e.g., Apple Secure Enclave, Android StrongBox, TPM) that can generate and store private keys with strong protection guarantees. However, signing operations using these enclaves are comparatively slow and may require user interaction (biometric confirmation, PIN entry).

For HTTP Message Signatures, where every request requires a signature, this creates a tension between security and performance. The jkt-jwt scheme resolves this by allowing the enclave key to sign a JWT that delegates authority to a faster ephemeral key:

1. The enclave generates a long-lived key pair (the identity key)
2. The device generates an ephemeral key pair in software (the signing key)
3. The enclave signs a JWT binding the ephemeral key via the `cnf` claim
4. HTTP requests are signed with the fast ephemeral key
5. The JWT proves the ephemeral key was authorized by the enclave key

The enclave key's JWK Thumbprint URI (`urn:jkt:<hash-algorithm>:<thumbprint>`) serves as a stable, pseudonymous device identity. Verifiers build trust in this identity over time (TOFU — Trust On First Use).

### Parameters

- `jwt` (REQUIRED, String) - Compact-serialized JWT

### JWT Requirements

**Header:**

- `typ` (REQUIRED) - Identifies the thumbprint hash algorithm. Defined values: `jkt-s256+jwt` (SHA-256), `jkt-s512+jwt` (SHA-512). Implementations MUST support `jkt-s256+jwt` and MAY support additional algorithms.
- `alg` (REQUIRED) - Signature algorithm used by the enclave key
- `jwk` (REQUIRED) - JWK public key of the enclave/identity key (the key that signed this JWT)

**Payload:**

- `iss` (REQUIRED) - JWK Thumbprint URI of the signing key, in the format `urn:jkt:<hash-algorithm>:<thumbprint>` where the thumbprint is computed per RFC 7638. The hash algorithm in the URN MUST match the algorithm indicated by the JWT `typ`. The verifier knows the hash algorithm from the `typ` it accepted, computes the thumbprint of the header `jwk`, prepends the known `urn:jkt:<hash-algorithm>:` prefix, and compares to `iss` by string equality.
- `iat` (REQUIRED) - Issued-at timestamp
- `exp` (REQUIRED) - Expiration timestamp
- `cnf` (REQUIRED) - Confirmation claim (RFC 7800) containing:
  - `jwk` - The ephemeral public key delegated for HTTP message signing

The `sub` claim is not used. The identity is the enclave key itself, fully represented by the `iss` thumbprint.

### JWT Type Registration

The `typ` value encodes both the purpose and the thumbprint hash algorithm:

| `typ` | Hash Algorithm | `iss` prefix |
|---|---|---|
| `jkt-s256+jwt` | SHA-256 | `urn:jkt:sha-256:` |
| `jkt-s512+jwt` | SHA-512 | `urn:jkt:sha-512:` |

The `jkt-` prefix indicates a self-issued delegation JWT: the signing key is embedded in the JWT header as a JWK, the issuer is identified by the key's thumbprint, and the JWT delegates signing authority to the key in the `cnf` claim. The suffix (`s256`, `s512`) identifies the hash algorithm used for the thumbprint. The `typ` and `iss` prefix MUST be consistent.

These types are independent of the Signature-Key header and MAY be used in other contexts where self-issued key delegation is needed. Additional hash algorithms can be supported by registering new `typ` values following the `jkt-<alg>+jwt` pattern.

### Example

```
Signature-Key: sig=jkt-jwt;jwt="eyJ..."
```

**JWT header:**

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

**JWT payload:**

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

### Verification Procedure

1. Parse the JWT without verifying the signature
2. Check the `typ` header (e.g., `jkt-s256+jwt`). Reject if the type is not supported.
3. Determine the hash algorithm and `iss` prefix from the `typ` (e.g., `jkt-s256+jwt` → SHA-256, `urn:jkt:sha-256:`)
4. Extract the `jwk` from the JWT header
5. Compute the JWK Thumbprint (RFC 7638) of the header `jwk` using the determined hash algorithm
6. Construct the expected `iss` value by prepending the known prefix to the computed thumbprint
7. Verify the `iss` claim matches the constructed value by string equality
8. Verify the JWT signature using the header `jwk`
9. Validate `exp` and `iat` claims per policy
10. Extract the ephemeral public key from `cnf.jwk`
11. Verify the HTTP Message Signature using the ephemeral key

### Comparison with Other Schemes

| | hwk | jkt-jwt | jwt |
|---|---|---|---|
| **Identity** | Key thumbprint | `urn:jkt:` thumbprint URI | Issuer URL |
| **Signing key** | Inline in header | Ephemeral, delegated via JWT | Ephemeral, delegated via JWT |
| **Identity key location** | Signature-Key header | JWT header `jwk` | Issuer's JWKS (via discovery) |
| **Trust model** | TOFU | TOFU | Issuer discovery |
| **Key discovery** | None (self-contained) | None (self-contained) | Well-known metadata |
| **Use case** | Simple pseudonymous signing | Enclave-backed delegation | Authority-backed delegation |

### Security Considerations

**Enclave binding**: The security of this scheme depends on the enclave key's private key remaining protected in hardware. If the enclave key is compromised, all delegated ephemeral keys are compromised. Verifiers should be aware that the jkt-jwt scheme implies but does not prove hardware protection — there is no attestation mechanism in this scheme.

**Ephemeral key lifetime**: The `exp` claim on the JWT controls how long the ephemeral key is valid. Shorter lifetimes limit the exposure window if an ephemeral key is compromised. Implementations SHOULD use the shortest practical lifetime.

**Self-issued trust**: Unlike the `jwt` scheme where trust is rooted in a discoverable issuer, jkt-jwt trust is rooted in the key itself. Verifiers MUST understand that any party can create a jkt-jwt — the scheme provides pseudonymous identity, not verified identity.

**Thumbprint as identifier**: The `iss` value is a JWK Thumbprint URI in the format `urn:jkt:<hash-algorithm>:<thumbprint>`. This is a globally unique, collision-resistant identifier. The verifier MUST always compute the expected `iss` from the header `jwk` and compare by string equality — never trust the `iss` value alone. Algorithm agility is achieved through the JWT `typ`: new hash algorithms require a new `typ` registration (e.g., `jkt-s512+jwt`), which determines both the hash algorithm and the expected `iss` prefix. The verifier never parses the `iss` value — it constructs the expected value and compares.

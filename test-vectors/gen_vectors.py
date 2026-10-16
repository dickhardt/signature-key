"""Spec-derived Signature-Key test vectors, for dickhardt/signature-key#25.

Written from draft-hardt-httpbis-signature-key-09 and RFC 9421, not from any
existing implementation. Every vector publishes the signature base verbatim,
which is what makes the SIGNER side checkable without a live peer: a published
signature only proves a verifier agrees with it, and for randomised algorithms
(ECDSA, RSA-PSS, ML-DSA hedged) no reproduce-the-bytes vector is constructible.

Keys are derived from fixed seeds so every value here is reproducible.
Run:  python3 gen_vectors.py
"""
import base64, hashlib, json, os, sys, textwrap

# dilithium-py supplies ML-DSA-44. Install it (`pip install dilithium-py`), or
# point PQLIB_PATH at a directory holding it.
if os.environ.get("PQLIB_PATH"):
    sys.path.insert(0, os.environ["PQLIB_PATH"])
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization

CREATED = 1791275958          # fixed, so vectors are stable
NOW     = 1791275958          # the instant a harness evaluates these at, per #25
B64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")

# ---------------------------------------------------------------- keys
def ed25519_from_seed(seed: bytes):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": B64(raw), "alg": "Ed25519"}
    priv = dict(jwk, d=B64(sk.private_bytes(serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw, serialization.NoEncryption())))
    return sk, jwk, priv

def p256_from_seed(seed: bytes):
    N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    d = (int.from_bytes(hashlib.sha256(seed).digest(), "big") % (N - 1)) + 1
    sk = ec.derive_private_key(d, ec.SECP256R1())
    n = sk.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "x": B64(n.x.to_bytes(32, "big")),
           "y": B64(n.y.to_bytes(32, "big")), "alg": "ES256"}
    priv = dict(jwk, d=B64(d.to_bytes(32, "big")))
    return sk, jwk, priv

def thumbprint(jwk, alg="sha256"):
    """RFC 7638 JWK thumbprint over the required members, lexicographic."""
    req = {"EC": ["crv", "kty", "x", "y"], "OKP": ["crv", "kty", "x"],
           "RSA": ["e", "kty", "n"]}[jwk["kty"]]
    canon = json.dumps({k: jwk[k] for k in req}, separators=(",", ":"), sort_keys=True)
    h = hashlib.sha256 if alg == "sha256" else hashlib.sha512
    return B64(h(canon.encode()).digest())

# ---------------------------------------------------------------- JWT
def jws(header: dict, payload: dict, signer, kind: str) -> str:
    seg = B64(json.dumps(header, separators=(",", ":")).encode()) + "." + \
          B64(json.dumps(payload, separators=(",", ":")).encode())
    if kind == "Ed25519":
        sig = signer.sign(seg.encode())
    else:
        der = signer.sign(seg.encode(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        r, s = decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return seg + "." + B64(sig)

# ---------------------------------------------------------------- base
def signature_base(method, url, headers, components, created):
    from urllib.parse import urlsplit
    u = urlsplit(url)
    derived = {"@method": method, "@authority": u.netloc, "@path": u.path,
               "@query": ("?" + u.query) if u.query else "?",
               "@target-uri": url, "@scheme": u.scheme}
    low = {k.lower(): v for k, v in headers.items()}
    covered = " ".join(f'"{c}"' for c in components)
    params = f"({covered});created={created}"
    lines = [f'"{c}": {derived[c] if c.startswith("@") else low[c]}' for c in components]
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines), params

# A negative whose Signature-Key member is itself the faulty part still carries
# a real signature, made with a key the header does not name. SIG_KEYS records
# which key produced which signature so the vector can publish it and a harness
# can establish that the signature is sound and the only fault is the one under
# test. Keyed by the base64 signature value, so it catches every signature
# whether it was built through signed_headers or inline.
SIGNER_KEYS = {}
SIG_KEYS = {}

def sign_base(base, signer, kind):
    if kind == "Ed25519":
        sig = signer.sign(base.encode())
    else:
        der = signer.sign(base.encode(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        r, s = decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    out = base64.b64encode(sig).decode()
    rec = SIGNER_KEYS.get(id(signer))
    if rec is not None:
        SIG_KEYS[out] = rec
    return out

def wrap8792(text, width=69):
    """RFC 8792 single-backslash line folding."""
    out = []
    for line in text.split("\n"):
        if len(line) <= width:
            out.append(line); continue
        while len(line) > width:
            out.append(line[:width] + "\\")
            line = line[width:]
        out.append(line)
    return "\n".join(out)

# ================================================================ vectors
ISSUER   = "https://issuer.example"
CLIENT   = "https://client.example"
RESOURCE = "https://resource.example"
TARGET   = "https://resource.example/api/documents"
COMPONENTS = ["@method", "@authority", "@path", "signature-key"]

# request key (signs the HTTP message) and issuer/enclave keys
rq_sk, rq_jwk, rq_priv = ed25519_from_seed(b"aauth-sigkey-vectors/request-key/v1")
is_sk, is_jwk, is_priv = p256_from_seed(b"aauth-sigkey-vectors/issuer-key/v1")
en_sk, en_jwk, en_priv = p256_from_seed(b"aauth-sigkey-vectors/enclave-key/v1")
sj_sk, sj_jwk, sj_priv = p256_from_seed(b"aauth-sigkey-vectors/self-jwt-key/v1")
ec_sk, ec_jwk, ec_priv = p256_from_seed(b"aauth-sigkey-vectors/request-key-ec/v1")
m2_sk, m2_jwk, m2_priv = ed25519_from_seed(b"aauth-sigkey-vectors/multi-sig-second-key/v1")

for _sk, _pub, _prv, _alg in (
        (rq_sk, rq_jwk, rq_priv, "Ed25519"),
        (m2_sk, dict(m2_jwk, kid="key-2"), dict(m2_priv, kid="key-2"), "Ed25519"),
        (is_sk, is_jwk, is_priv, "ES256"),
        (en_sk, en_jwk, en_priv, "ES256"),
        (sj_sk, sj_jwk, sj_priv, "ES256"),
        (ec_sk, ec_jwk, ec_priv, "ES256")):
    SIGNER_KEYS[id(_sk)] = {"public_jwk": _pub, "private_jwk": _prv, "alg": _alg}

VECTORS = []

def emit(name, scheme, sigkey_hdr, method, url, signer, kind, pub, priv,
         notes, extra=None, deterministic=True, label="sig"):
    headers = {"Signature-Key": sigkey_hdr}
    base, params = signature_base(method, url, headers, COMPONENTS, CREATED)
    sig = sign_base(base, signer, kind)
    v = {
        "name": name, "scheme": scheme, "now": NOW,
        "vector_category": (3 if deterministic else 2),
        "request": {"method": method, "target_uri": url,
                    "headers": {"Signature-Key": sigkey_hdr}},
        "covered_components": COMPONENTS,
        "signature_params": params,
        "signature_base": base,
        "signature_base_sha256": hashlib.sha256(base.encode()).hexdigest(),
        "signature_base_length": len(base.encode()),
        "expected_headers": {
            "Signature-Input": f"{label}=({' '.join(chr(34)+c+chr(34) for c in COMPONENTS)});created={CREATED}",
            "Signature": f"{label}=:{sig}:",
            "Signature-Key": sigkey_hdr,
        },
        "key": {"public_jwk": pub, "private_jwk": priv, "alg": pub["alg"]},
        "signature_is_reproducible": deterministic,
        "notes": notes,
    }
    if extra:
        v.update(extra)
    VECTORS.append(v)
    return v

# ---- 1. hwk, OKP/Ed25519 ---------------------------------------
emit("hwk-okp-ed25519", "hwk",
     f'sig=hwk;kty="OKP";crv="Ed25519";x="{rq_jwk["x"]}";alg="Ed25519"',
     "GET", TARGET, rq_sk, "Ed25519", rq_jwk, rq_priv,
     "Inline OKP key. No kid, forbidden by the hwk scheme: the key is carried "
     "inline so there is nothing for an identifier to select. Ed25519 is "
     "deterministic (RFC 8032), so the Signature value reproduces byte for byte.")

# ---- 2. hwk, EC/P-256 ------------------------------------------
emit("hwk-ec-p256", "hwk",
     f'sig=hwk;kty="EC";crv="P-256";x="{ec_jwk["x"]}";y="{ec_jwk["y"]}";alg="ES256"',
     "GET", TARGET, ec_sk, "ES256", ec_jwk, ec_priv,
     "Inline EC key. ECDSA is randomised, so the Signature value here is ONE "
     "valid signature, not the only one. Compare the signature base, then "
     "verify the signature; do not compare signature bytes.",
     deterministic=False)

# ---- 3. jkt-jwt ------------------------------------------------
jkt_tp = thumbprint(en_jwk, "sha256")
jkt_iss = f"urn:jkt:sha-256:{jkt_tp}"
jkt = jws({"typ": "jkt-s256+jwt", "alg": "ES256", "jwk": en_jwk},
          {"iss": jkt_iss, "iat": CREATED - 60, "exp": CREATED + 86400,
           "cnf": {"jwk": rq_jwk}}, en_sk, "ES256")
emit("jkt-jwt-enclave-p256-delegates-ed25519", "jkt-jwt",
     f'sig=jkt-jwt;jwt="{jkt}"',
     "GET", TARGET, rq_sk, "Ed25519", rq_jwk, rq_priv,
     "Enclave P-256 identity key delegates to an Ed25519 ephemeral request key "
     "via cnf.jwk. iss is the RFC 7638 thumbprint of the HEADER jwk, prefixed "
     "per the typ. The HTTP signature is made by the cnf.jwk key, not the "
     "enclave key. The delegation JWT itself is ECDSA and so not reproducible; "
     "the HTTP signature is Ed25519 and is.",
     extra={"delegation_jwt": {
         "compact": jkt,
         "header": {"typ": "jkt-s256+jwt", "alg": "ES256", "jwk": en_jwk},
         "payload": {"iss": jkt_iss, "iat": CREATED - 60,
                     "exp": CREATED + 86400, "cnf": {"jwk": rq_jwk}},
         "enclave_private_jwk": en_priv,
         "thumbprint_input": json.dumps(
             {k: en_jwk[k] for k in ["crv", "kty", "x", "y"]},
             separators=(",", ":"), sort_keys=True),
         "thumbprint_sha256": jkt_tp}})

# ---- 4. jwks_uri -----------------------------------------------
DWK = "example-configuration"
emit("jwks_uri-discovery-ed25519", "jwks_uri",
     f'sig=jwks_uri;id="{CLIENT}";dwk="{DWK}";kid="key-1"',
     "GET", TARGET, rq_sk, "Ed25519", dict(rq_jwk, kid="key-1"),
     dict(rq_priv, kid="key-1"),
     "Two-hop discovery. The metadata document MUST carry issuer, and issuer "
     "MUST equal the id parameter by byte equality as presented. The alg "
     "travels only on the resolved JWKS entry, because the header conveys id, "
     "dwk and kid, which identify a key rather than describe it.",
     extra={"discovery": {
         "metadata_url": f"{CLIENT}/.well-known/{DWK}",
         "metadata_document": {"issuer": CLIENT,
                               "jwks_uri": f"{CLIENT}/jwks.json"},
         "jwks_url": f"{CLIENT}/jwks.json",
         "jwks": {"keys": [dict(rq_jwk, kid="key-1", use="sig")]}}})

# ---- 5. jwks ---------------------------------------------------
emit("jwks-direct-ed25519", "jwks",
     f'sig=jwks;url="{CLIENT}/keys.jwks";kid="key-1"',
     "GET", TARGET, rq_sk, "Ed25519", dict(rq_jwk, kid="key-1"),
     dict(rq_priv, kid="key-1"),
     "One hop, no metadata document. The URL is both identifier and key "
     "location, compared by byte equality and never canonicalised, so any "
     "byte difference names a different signer.",
     extra={"discovery": {
         "jwks_url": f"{CLIENT}/keys.jwks",
         "jwks": {"keys": [dict(rq_jwk, kid="key-1", use="sig")]}}})

# ---- 6. jwt (cnf confirmation key) -----------------------------
jwt_tok = jws({"typ": "aa-token+jwt", "alg": "ES256", "kid": "issuer-1"},
              {"iss": ISSUER, "dwk": DWK, "sub": "instance-123",
               "iat": CREATED - 60, "exp": CREATED + 3600,
               "cnf": {"jwk": rq_jwk}}, is_sk, "ES256")
emit("jwt-cnf-ed25519", "jwt",
     f'sig=jwt;jwt="{jwt_tok}"',
     "GET", TARGET, rq_sk, "Ed25519", rq_jwk, rq_priv,
     "Issuer-minted assertion carrying the request key in cnf.jwk. exp is "
     "MUST, it is what bounds how long the confirmation key is accepted. "
     "No cache parameter, so no jti is required here.",
     extra={"assertion_jwt": {
         "compact": jwt_tok,
         "header": {"typ": "aa-token+jwt", "alg": "ES256", "kid": "issuer-1"},
         "payload": {"iss": ISSUER, "dwk": DWK, "sub": "instance-123",
                     "iat": CREATED - 60, "exp": CREATED + 3600,
                     "cnf": {"jwk": rq_jwk}},
         "issuer_private_jwk": is_priv},
         "discovery": {
             "metadata_url": f"{ISSUER}/.well-known/{DWK}",
             "metadata_document": {"issuer": ISSUER,
                                   "jwks_uri": f"{ISSUER}/jwks.json"},
             "jwks": {"keys": [dict(is_jwk, kid="issuer-1", use="sig")]}}})

# ---- 7. jwt with cache (jti REQUIRED) --------------------------
jwt_c = jws({"typ": "aa-token+jwt", "alg": "ES256", "kid": "issuer-1"},
            {"iss": ISSUER, "dwk": DWK, "sub": "instance-123",
             "iat": CREATED - 60, "exp": CREATED + 3600,
             "jti": "4f1a9c7e-2b60-4e2a-9f3d-7c1b05e8a412",
             "cnf": {"jwk": rq_jwk}}, is_sk, "ES256")
emit("jwt-cnf-ed25519-cache-requested", "jwt",
     f'sig=jwt;jwt="{jwt_c}";cache',
     "GET", TARGET, rq_sk, "Ed25519", rq_jwk, rq_priv,
     "Same as jwt-cnf-ed25519 plus the cache parameter. Boolean true is "
     "serialised by omitting the value per RFC 9651 4.1.1.2, so it appears as "
     "'cache' and not 'cache=?1'. A JWT presented with cache MUST carry jti; "
     "a verifier MUST NOT issue a cache identifier for one without it. The "
     "parameter sits inside the covered signature-key component, so the "
     "request signature covers the cache request itself.",
     extra={"assertion_jwt": {"compact": jwt_c, "jti":
         "4f1a9c7e-2b60-4e2a-9f3d-7c1b05e8a412",
         "issuer_private_jwk": is_priv}})

# ---- 8. self-jwt -----------------------------------------------
self_tok = jws({"alg": "ES256", "kid": "r1", "typ": "aa-event+jwt"},
               {"iss": RESOURCE, "dwk": "aauth-resource.json",
                "sub": "resource-instance-7", "aud": CLIENT,
                "iat": CREATED - 60, "exp": CREATED + 300},
               sj_sk, "ES256")
emit("self-jwt-es256", "self-jwt",
     f'sig=self-jwt;jwt="{self_tok}"',
     "GET", TARGET, sj_sk, "ES256", dict(sj_jwk, kid="r1"),
     dict(sj_priv, kid="r1"),
     "Issuer and signer are the same party, so one key verifies both the JWT "
     "and the HTTP message signature. cnf MUST be absent, and a verifier MUST "
     "reject a self-jwt that carries one. No cache parameter is supported for "
     "this scheme. Both signatures are ECDSA, so neither reproduces byte for "
     "byte; compare the base and verify.",
     deterministic=False,
     extra={"assertion_jwt": {
         "compact": self_tok,
         "header": {"alg": "ES256", "kid": "r1", "typ": "aa-event+jwt"},
         "payload": {"iss": RESOURCE, "dwk": "aauth-resource.json",
                     "sub": "resource-instance-7", "aud": CLIENT,
                     "iat": CREATED - 60, "exp": CREATED + 300},
         "cnf_present": False},
         "discovery": {
             "metadata_url": f"{RESOURCE}/.well-known/aauth-resource.json",
             "metadata_document": {"issuer": RESOURCE,
                                   "jwks_uri": f"{RESOURCE}/jwks.json"},
             "jwks": {"keys": [dict(sj_jwk, kid="r1", use="sig")]}}})

# ---- 9. multiple signatures, both covering signature-key -------
multi_hdr = (f'sig1=hwk;kty="OKP";crv="Ed25519";x="{rq_jwk["x"]}";alg="Ed25519", '
             f'sig2=jwks;url="{CLIENT}/second.jwks";kid="key-2"')
mh = {"Signature-Key": multi_hdr}
b1, p1 = signature_base("GET", TARGET, mh, COMPONENTS, CREATED)
s1 = sign_base(b1, rq_sk, "Ed25519")
s2 = sign_base(b1, m2_sk, "Ed25519")
assert s1 != s2, "the two labels must not collapse to one signature"
VECTORS.append({
    "name": "multi-signature-hwk-and-jwks", "scheme": "hwk+jwks",
    "now": NOW, "vector_category": 3,
    "request": {"method": "GET", "target_uri": TARGET,
                "headers": {"Signature-Key": multi_hdr}},
    "covered_components": COMPONENTS,
    "signature_params": p1,
    "signature_base": b1,
    "signature_base_sha256": hashlib.sha256(b1.encode()).hexdigest(),
    "signature_base_length": len(b1.encode()),
    "expected_headers": {
        "Signature-Input": f'sig1=({" ".join(chr(34)+c+chr(34) for c in COMPONENTS)});created={CREATED}, '
                           f'sig2=({" ".join(chr(34)+c+chr(34) for c in COMPONENTS)});created={CREATED}',
        "Signature": f"sig1=:{s1}:, sig2=:{s2}:",
        "Signature-Key": multi_hdr},
    "key": {"public_jwk": rq_jwk, "private_jwk": rq_priv, "alg": "Ed25519"},
    "keys": {
        "sig1": {"public_jwk": rq_jwk, "private_jwk": rq_priv, "alg": "Ed25519"},
        "sig2": {"public_jwk": dict(m2_jwk, kid="key-2"),
                 "private_jwk": dict(m2_priv, kid="key-2"), "alg": "Ed25519"}},
    "discovery": {"jwks_url": f"{CLIENT}/second.jwks",
                  "jwks": {"keys": [dict(m2_jwk, kid="key-2", use="sig")]}},
    "signature_is_reproducible": True,
    "notes": "Both labels cover signature-key, and the COMPLETE Signature-Key "
             "header was populated before either signature was made, so each "
             "signature protects both members' key material. Both labels "
             "therefore share one identical signature base. The two members "
             "resolve to DIFFERENT keys, so the two signatures over that one "
             "base differ, which is what makes the vector able to catch a "
             "verifier that resolves one label and reuses its key for the "
             "other. Each member is resolved independently: sig1 from the "
             "inline hwk key, sig2 from its own url and kid. Label "
             "correlation is by equality of label name across "
             "Signature-Input, Signature and Signature-Key. Per-label key "
             "material is under keys; key repeats sig1 for harnesses that "
             "expect a single key.",
})


def signed_headers(sigkey_hdr, signer, kind, components=None, label="sig"):
    """Build a COMPLETE signed request: Signature-Input, Signature, Signature-Key.

    A must-reject vector has to be a real signed request with exactly one fault,
    or an end-to-end verifier stops at invalid_signature before it reaches the
    rule under test. The signature here is always valid over the base; the fault
    lives in the Signature-Key member or in what it resolves to.
    """
    comps = components or COMPONENTS
    base, params = signature_base("GET", TARGET, {"Signature-Key": sigkey_hdr},
                                  comps, CREATED)
    sig = sign_base(base, signer, kind)
    hdrs = {
        "Signature-Input": f'{label}=({" ".join(chr(34)+c+chr(34) for c in comps)});created={CREATED}',
        "Signature": f"{label}=:{sig}:",
        "Signature-Key": sigkey_hdr,
    }
    return hdrs, base, params

# ================================================================ negatives
# Each is derived from a MUST / MUST NOT in the draft, cited by section name.
NEG = []
def neg(name, sigkey_hdr, rule, expect_error, cite, extra=None,
        signer=None, kind="Ed25519", unsigned_reason=None):
    if unsigned_reason:
        headers = {"Signature-Key": sigkey_hdr}
        base, params = signature_base("GET", TARGET, headers, COMPONENTS, CREATED)
    else:
        headers, base, params = signed_headers(sigkey_hdr,
                                               signer if signer is not None else rq_sk,
                                               kind)
    e = {"name": name, "vector_category": 1, "now": NOW,
         "request": {"method": "GET", "target_uri": TARGET,
         "headers": headers},
         "signature_base": base,
         "signature_base_sha256": hashlib.sha256(base.encode()).hexdigest(),
         "signature_base_length": len(base.encode()),
         "must_reject": True, "expected_signature_error": expect_error,
         "rule": rule, "draft_section": cite}
    if unsigned_reason:
        e["unsigned"] = True
        e["unsigned_reason"] = unsigned_reason
    if extra: e.update(extra)
    NEG.append(e)

neg("hwk-with-kid-forbidden",
    f'sig=hwk;kty="OKP";crv="Ed25519";x="{rq_jwk["x"]}";alg="Ed25519";kid="k1"',
    "The kid parameter MUST NOT be used with hwk. The key is carried inline, "
    "so there is nothing for an identifier to select, and a kid that disagrees "
    "with the inline key has no defined resolution. This is a member the "
    "document forbids: understood and rejected, not unknown and ignored.",
    "invalid_key", "Header Web Key (hwk) / Constraints")

neg("hwk-alg-absent",
    f'sig=hwk;kty="OKP";crv="Ed25519";x="{rq_jwk["x"]}"',
    "A verifier MUST reject a JWK whose alg member is absent, and MUST NOT "
    "select an algorithm for it by inspecting other key parameters. kty and "
    "crv would determine it here; the draft requires alg regardless.",
    "unsupported_algorithm", "Algorithm Determination")

neg("hwk-alg-polymorphic-eddsa",
    f'sig=hwk;kty="OKP";crv="Ed25519";x="{rq_jwk["x"]}";alg="EdDSA"',
    "The polymorphic EdDSA identifier MUST NOT be used. Use the "
    "fully-specified Ed25519 or Ed448 identifiers of RFC 9864.",
    "unsupported_algorithm", "Algorithm Determination")

neg("hwk-alg-kty-inconsistent",
    f'sig=hwk;kty="RSA";n="0vx7agoebGcQSuuPiLJXZpt";e="AQAB";alg="ES256"',
    "A verifier MUST verify kty and, where present, crv are consistent with "
    "alg, and MUST reject the key if they are not. alg ES256 with kty RSA is "
    "inconsistent. Rejecting on disagreement stops a key being used under "
    "either of two conflicting interpretations.",
    "invalid_key", "Algorithm Determination")

neg("hwk-alg-crv-inconsistent",
    f'sig=hwk;kty="EC";crv="P-384";x="{ec_jwk["x"]}";y="{ec_jwk["y"]}";alg="ES256"',
    "Same rule on the curve: alg ES256 with crv P-384 is inconsistent and "
    "MUST be rejected.",
    "invalid_key", "Algorithm Determination")

neg("hwk-symmetric-forbidden",
    'sig=hwk;kty="oct";k="c2VjcmV0LWtleS1tYXRlcmlhbA";alg="HS256"',
    "Symmetric algorithms MUST NOT be used. The oct key type and the JOSE MAC "
    "identifiers name a shared secret rather than a public key, and a verifier "
    "MUST reject a scheme that conveys or references such a key.",
    "unsupported_algorithm", "Algorithm Determination / Symmetric Algorithms",
    unsigned_reason=("kty is oct. The scheme defines no symmetric mode, so there is no "
                     "signing procedure for the key this member declares. Signing with "
                     "an unrelated asymmetric key would add a second fault and make the "
                     "vector test the wrong thing."))

neg("unknown-scheme-selected",
    'sig=quantum-widget;blob="AAAA"',
    "A verifier that selects a member whose scheme token it does not "
    "implement, including any unregistered value, MUST reject with "
    "unsupported_scheme and MUST NOT fail in a scheme-specific or undefined "
    "manner. Dispatch SHOULD be a registry lookup, not a fixed set of branches.",
    "unsupported_scheme", "Signature-Key Header / Unknown schemes",
    unsigned_reason=("the selected scheme is unknown by construction, so no signing "
                     "procedure is defined for it. A signature made under some other "
                     "scheme is not the thing the verifier is asked to reject."))

_self_cnf = jws({"alg": "ES256", "kid": "r1", "typ": "aa-event+jwt"},
                {"iss": RESOURCE, "dwk": "aauth-resource.json",
                 "iat": CREATED - 60, "exp": CREATED + 300,
                 "cnf": {"jwk": rq_jwk}}, sj_sk, "ES256")
neg("self-jwt-with-cnf-forbidden",
    f'sig=self-jwt;jwt="{_self_cnf}"',
    "Verifiers MUST validate that cnf is absent before treating the scheme as "
    "self-issued; a JWT containing cnf MUST be rejected. A self-jwt's signing "
    "key IS its confirmation key, so a cnf claim is a different trust model "
    "wearing this scheme's name.",
    "invalid_jwt", "Self-Issued JWT (self-jwt) / Security Considerations",
    extra={"assertion_jwt": {"compact": _self_cnf,
                             "offending_claim": "cnf"}})

neg("jwks_uri-issuer-mismatch",
    f'sig=jwks_uri;id="https://mismatch.example";dwk="{DWK}";kid="key-1"',
    "The metadata document's issuer MUST equal the id parameter by byte "
    "equality as presented. Without the check, a document served under id "
    "through shared hosting or subdomain takeover could point jwks_uri at keys "
    "that do not belong to id, and the verifier would attribute the request "
    "accordingly.",
    "issuer_mismatch", "JWKS URI Discovery (jwks_uri) / Discovery procedure",
    extra={"discovery": {
        "metadata_url": f"https://mismatch.example/.well-known/{DWK}",
        "metadata_document": {"issuer": "https://attacker.example",
                              "jwks_uri": "https://attacker.example/jwks.json"}}})

neg("jwks_uri-issuer-missing",
    f'sig=jwks_uri;id="https://nodoc.example";dwk="{DWK}";kid="key-1"',
    "The document MUST contain issuer and jwks_uri. Reject with issuer_missing "
    "if issuer is absent.",
    "issuer_missing", "JWKS URI Discovery (jwks_uri) / Discovery procedure",
    extra={"discovery": {
        "metadata_url": f"https://nodoc.example/.well-known/{DWK}",
        "metadata_document": {"jwks_uri": "https://nodoc.example/jwks.json"}}})

# label consistency: present in Signature-Input/Signature, absent from Signature-Key
_lc_hdr = f'other=hwk;kty="OKP";crv="Ed25519";x="{rq_jwk["x"]}";alg="Ed25519"'
_lc_base, _lc_params = signature_base("GET", TARGET,
                                      {"Signature-Key": _lc_hdr}, COMPONENTS, CREATED)
# a real signature under label sig, so the only fault is the missing member
_lc_sig = sign_base(_lc_base, rq_sk, "Ed25519")
NEG.append({
    "name": "label-missing-from-signature-key",
    "vector_category": 1, "now": NOW,
    "request": {"method": "GET", "target_uri": TARGET,
                "headers": {
                    "Signature-Input": f'sig=({" ".join(chr(34)+c+chr(34) for c in COMPONENTS)});created={CREATED}',
                    "Signature": f"sig=:{_lc_sig}:",
                    "Signature-Key": _lc_hdr}},
    "signature_base": _lc_base,
    "signature_base_sha256": hashlib.sha256(_lc_base.encode()).hexdigest(),
    "signature_base_length": len(_lc_base.encode()),
    "must_reject": True, "expected_signature_error": "invalid_key",
    "rule": "If the Signature-Key header is present and the verifier is "
            "attempting to verify a label using it, but the corresponding "
            "dictionary member is missing, verification for that signature "
            "MUST fail. Here the verifier wants label 'sig' and Signature-Key "
            "carries only 'other'.",
    "draft_section": "Label Correlation / Label Consistency"})

# the inverse MUST NOT: an unselected member naming an unknown scheme is ignored
_ok_hdr = (f'sig=hwk;kty="OKP";crv="Ed25519";x="{rq_jwk["x"]}";alg="Ed25519", '
           f'future=quantum-widget;blob="AAAA"')
_ok_base, _ok_params = signature_base("GET", TARGET,
                                      {"Signature-Key": _ok_hdr}, COMPONENTS, CREATED)
_ok_sig = sign_base(_ok_base, rq_sk, "Ed25519")
NEG.append({
    "name": "unselected-member-unknown-scheme-MUST-ACCEPT",
    "vector_category": 1, "now": NOW,
    "request": {"method": "GET", "target_uri": TARGET,
                "headers": signed_headers(_ok_hdr, rq_sk, "Ed25519")[0]},
    "signature_base": _ok_base,
    "signature_base_sha256": hashlib.sha256(_ok_base.encode()).hexdigest(),
    "signature_base_length": len(_ok_base.encode()),
    "must_reject": False,
    "expected_headers": {
        "Signature-Input": f'sig=({" ".join(chr(34)+c+chr(34) for c in COMPONENTS)});created={CREATED}',
        "Signature": f"sig=:{_ok_sig}:",
        "Signature-Key": _ok_hdr},
    "key": {"public_jwk": rq_jwk, "private_jwk": rq_priv, "alg": "Ed25519"},
    "rule": "A verifier MUST NOT reject a request because a member it did not "
            "select names a scheme the verifier does not implement. This is "
            "the companion to unsupported_scheme and the one a naive "
            "implementation fails: without it no signer could offer a new "
            "scheme without breaking every verifier that lacks it, so none "
            "would, and the registry would have no path into deployment. "
            "Verify label 'sig' and ignore 'future'.",
    "draft_section": "Signature-Key Header / Unknown schemes + Label Consistency"})


# ================================================================ ML-DSA / AKP
# Issue #25 calls these the highest-value single vector, and the value is
# mostly for implementations that CANNOT do ML-DSA. Nothing is signed in the
# key-handling pair, so every implementation can run them today.
try:
    from dilithium_py.ml_dsa import ML_DSA_44
except ImportError:
    raise SystemExit(
        "ML-DSA-44 vectors need dilithium-py.\n"
        "  pip install dilithium-py\n"
        "or set PQLIB_PATH to a directory containing it.")

def mldsa_from_seed(seed: bytes):
    # FIPS 204 ML-DSA.KeyGen_internal takes a 32-byte zeta, so a fixed seed
    # gives a reproducible key pair.
    pk, sk = ML_DSA_44._keygen_internal(hashlib.sha256(seed).digest())
    jwk = {"kty": "AKP", "alg": "ML-DSA-44", "pub": B64(pk)}
    return pk, sk, jwk, dict(jwk, priv=B64(sk))

pq_pk, pq_sk, pq_jwk, pq_priv = mldsa_from_seed(b"aauth-sigkey-vectors/mldsa-44/v1")

# FIPS 204 hedged signing draws rnd from an RBG, which would make the published
# file differ on every run. Feed it a fixed stream instead. The signature stays
# a genuine hedged signature, with a non-zero rnd; it is only the GENERATOR that
# becomes deterministic. That is not the same as the vector being
# reproduce-the-bytes: another signer's rnd differs, so it stays category 2.
_pq_stream = hashlib.sha256(b"aauth-sigkey-vectors/mldsa-44/rnd/v1").digest()
def _fixed_random(n: int) -> bytes:
    out = b""
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(_pq_stream + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return out[:n]
ML_DSA_44.random_bytes = staticmethod(_fixed_random)

AKP_NOTE = (f"ML-DSA-44 key, {len(pq_pk)} byte public value per FIPS 204, carried "
            f"as the AKP key type of RFC 9964 with the algorithm named by alg "
            f"rather than derivable from the key structure.")

# ---- A. JWKS holding ONLY an ML-DSA-44 key ---------------------
# Signed with the ML-DSA key the JWKS actually holds, so the request is complete
# and the single fault is that the verifier does not implement that key type.
_akp_hdr = f'sig=jwks;url="{CLIENT}/pq.jwks";kid="pq-1"'
_akp_base, _ = signature_base("GET", TARGET, {"Signature-Key": _akp_hdr},
                              COMPONENTS, CREATED)
_akp_sig = base64.b64encode(
    ML_DSA_44.sign(pq_sk, _akp_base.encode(), deterministic=True)).decode()
NEG.append({
    "name": "akp-only-jwks-must-decline-not-throw",
    "vector_category": 1, "now": NOW,
    "request": {"method": "GET", "target_uri": TARGET, "headers": {
        "Signature-Input": f'sig=({" ".join(chr(34)+c+chr(34) for c in COMPONENTS)});created={CREATED}',
        "Signature": f"sig=:{_akp_sig}:",
        "Signature-Key": _akp_hdr}},
    "signing_key": SIG_KEYS.setdefault(_akp_sig, {
        "public_jwk": dict(pq_jwk, kid="pq-1"),
        "private_jwk": dict(pq_priv, kid="pq-1"), "alg": "ML-DSA-44"}),
    "signature_base": _akp_base,
    "signature_base_sha256": hashlib.sha256(_akp_base.encode()).hexdigest(),
    "signature_base_length": len(_akp_base.encode()),
    "must_reject": True, "expected_signature_error": "unsupported_algorithm",
    "rule": "A verifier that encounters a JWK whose kty it does not implement, "
            "including the AKP key type, MUST reject the key with defined error "
            "feedback and MUST NOT fail in an undefined manner. Absence of "
            "support for a key type is a reason to decline, not a parsing "
            "failure. An implementation without ML-DSA must report "
            "unsupported_algorithm here rather than throw. " + AKP_NOTE,
    "draft_section": "Algorithm Determination",
    "discovery": {"jwks_url": f"{CLIENT}/pq.jwks",
                  "jwks": {"keys": [dict(pq_jwk, kid="pq-1", use="sig")]}}})

# ---- B. mixed JWKS, the Ed25519 key selected by kid ------------
mixed_hdr = f'sig=jwks;url="{CLIENT}/mixed.jwks";kid="classic-1"'
mb, mp = signature_base("GET", TARGET, {"Signature-Key": mixed_hdr},
                        COMPONENTS, CREATED)
ms = sign_base(mb, rq_sk, "Ed25519")
NEG.append({
    "name": "mixed-jwks-ignore-unparseable-neighbour-MUST-ACCEPT",
    "vector_category": 1, "now": NOW,
    "request": {"method": "GET", "target_uri": TARGET,
                "headers": {"Signature-Input": f'sig=({" ".join(chr(34)+c+chr(34) for c in COMPONENTS)});created={CREATED}',
                            "Signature": f"sig=:{ms}:",
                            "Signature-Key": mixed_hdr}},
    "signature_base": mb,
    "signature_base_sha256": hashlib.sha256(mb.encode()).hexdigest(),
    "signature_base_length": len(mb.encode()),
    "must_reject": False,
    "expected_headers": {
        "Signature-Input": f'sig=({" ".join(chr(34)+c+chr(34) for c in COMPONENTS)});created={CREATED}',
        "Signature": f"sig=:{ms}:",
        "Signature-Key": mixed_hdr},
    "key": {"public_jwk": dict(rq_jwk, kid="classic-1"),
            "private_jwk": dict(rq_priv, kid="classic-1"), "alg": "Ed25519"},
    "rule": "The JWKS holds an Ed25519 key and an ML-DSA-44 key, and the "
            "vector selects the Ed25519 one by kid. A verifier MUST select the "
            "member matching kid without requiring any other member to be "
            "usable, and MUST NOT fail because an unselected member names a "
            "kty or alg it does not implement. The failure mode is a library "
            "that hits the unknown kty while enumerating and abandons a "
            "perfectly good key sitting next to it. Exercising the "
            "unknown-value path routinely is what stops it rotting, in the "
            "spirit of RFC 9170. " + AKP_NOTE,
    "draft_section": "Algorithm Determination, final paragraphs",
    "discovery": {"jwks_url": f"{CLIENT}/mixed.jwks",
                  "jwks": {"keys": [dict(rq_jwk, kid="classic-1", use="sig"),
                                    dict(pq_jwk, kid="pq-1", use="sig")]}}})

# ---- C. ML-DSA-44 verify-only signature vector -----------------
pq_hdr = f'sig=jwks;url="{CLIENT}/pq.jwks";kid="pq-1"'
pqb, pqp = signature_base("GET", TARGET, {"Signature-Key": pq_hdr},
                          COMPONENTS, CREATED)
pq_sig = ML_DSA_44.sign(pq_sk, pqb.encode())                  # hedged, default
pq_det = ML_DSA_44.sign(pq_sk, pqb.encode(), deterministic=True)
assert ML_DSA_44.verify(pq_pk, pqb.encode(), pq_sig)
assert ML_DSA_44.verify(pq_pk, pqb.encode(), pq_det)
assert pq_sig != pq_det, "hedged and deterministic must differ"
VECTORS.append({
    "name": "mldsa-44-verify-only", "scheme": "jwks", "now": NOW,
    "vector_category": 2,
    "request": {"method": "GET", "target_uri": TARGET,
                "headers": {"Signature-Key": pq_hdr}},
    "covered_components": COMPONENTS,
    "signature_params": pqp,
    "signature_base": pqb,
    "signature_base_sha256": hashlib.sha256(pqb.encode()).hexdigest(),
    "signature_base_length": len(pqb.encode()),
    "expected_headers": {
        "Signature-Input": f'sig=({" ".join(chr(34)+c+chr(34) for c in COMPONENTS)});created={CREATED}',
        "Signature": f"sig=:{base64.b64encode(pq_sig).decode()}:",
        "Signature-Key": pq_hdr},
    "key": {"public_jwk": dict(pq_jwk, kid="pq-1"),
            "private_jwk": dict(pq_priv, kid="pq-1"), "alg": "ML-DSA-44"},
    "signature_is_reproducible": False,
    "notes": "Verify-only, category 2. ML-DSA sits here on exactly the same "
             "footing as ECDSA and RSA-PSS: FIPS 204 specifies the hedged "
             "variant as the default, so a second run produces a different "
             f"signature. Signature is {len(pq_sig)} bytes. Verification is "
             "deterministic, so any implementation supporting the algorithm "
             "gets a definite answer from this vector. " + AKP_NOTE,
    "discovery": {"jwks_url": f"{CLIENT}/pq.jwks",
                  "jwks": {"keys": [dict(pq_jwk, kid="pq-1", use="sig")]}}})

# ---- D. the same base signed deterministically, OPTIONAL -------
VECTORS.append({
    "name": "mldsa-44-deterministic-optional", "scheme": "jwks", "now": NOW,
    "vector_category": 3, "conformance": "OPTIONAL",
    "request": {"method": "GET", "target_uri": TARGET,
                "headers": {"Signature-Key": pq_hdr}},
    "covered_components": COMPONENTS,
    "signature_params": pqp,
    "signature_base": pqb,
    "signature_base_sha256": hashlib.sha256(pqb.encode()).hexdigest(),
    "signature_base_length": len(pqb.encode()),
    "expected_headers": {
        "Signature-Input": f'sig=({" ".join(chr(34)+c+chr(34) for c in COMPONENTS)});created={CREATED}',
        "Signature": f"sig=:{base64.b64encode(pq_det).decode()}:",
        "Signature-Key": pq_hdr},
    "key": {"public_jwk": dict(pq_jwk, kid="pq-1"),
            "private_jwk": dict(pq_priv, kid="pq-1"), "alg": "ML-DSA-44"},
    "signature_is_reproducible": True,
    "notes": "The same base as mldsa-44-verify-only, signed with the "
             "deterministic variant of FIPS 204, where rnd is all zeros. The "
             "hedged variant degrades to exactly this when the RBG returns "
             "zeros, so an implementation that can inject rnd reproduces these "
             "bytes. Most libraries do not expose that knob, so this vector is "
             "OPTIONAL and MUST NOT be required to pass. It is published "
             "because for the implementations that can reach it, it is the "
             "only ML-DSA vector that tests a SIGNER rather than a verifier. "
             + AKP_NOTE,
    "discovery": {"jwks_url": f"{CLIENT}/pq.jwks",
                  "jwks": {"keys": [dict(pq_jwk, kid="pq-1", use="sig")]}}})

# ================================================================ gaps from #25
# ---- signature-key absent from covered components --------------
_nc = ["@method", "@authority", "@path"]
_nc_hdr = f'sig=hwk;kty="OKP";crv="Ed25519";x="{rq_jwk["x"]}";alg="Ed25519"'
_nc_base, _ = signature_base("GET", TARGET, {"Signature-Key": _nc_hdr}, _nc, CREATED)
NEG.append({
    "name": "signature-key-not-covered",
    "vector_category": 1, "now": NOW,
    "request": {"method": "GET", "target_uri": TARGET,
                "headers": signed_headers(_nc_hdr, rq_sk, "Ed25519", components=_nc)[0]},
    "covered_components": _nc,
    "signature_base": _nc_base,
    "signature_base_sha256": hashlib.sha256(_nc_base.encode()).hexdigest(),
    "signature_base_length": len(_nc_base.encode()),
    "must_reject": True, "expected_signature_error": "invalid_input",
    "expected_signature_error_members": {
        "required_input": '("@method" "@authority" "@path" "signature-key")'},
    "rule": "Every signature MUST cover the signature-key component, so that "
            "the signature protects the key material that verifies it. Here "
            "the signer covered the first three and left signature-key out, "
            "which leaves the key material unprotected and swappable. The "
            "server SHOULD answer invalid_input with a required_input member "
            "naming the components it requires, and MAY omit that member where "
            "enumerating its requirements to an unauthenticated caller is a "
            "disclosure risk.",
    "draft_section": "invalid_input / Signature-Key Integrity"})

# ---- kid selects nothing in the JWKS ---------------------------
neg("jwks-kid-not-in-jwks",
    f'sig=jwks;url="{CLIENT}/keys.jwks";kid="rotated-away"',
    "The kid selects no member of the fetched JWKS. The verifier rejects with "
    "unknown_key rather than falling back to another member: a JWKS with one "
    "usable key is not licence to use it for a kid that does not name it. The "
    "server SHOULD re-fetch the JWKS once before answering, to handle a key "
    "that rotated between the signer publishing and the verifier reading.",
    "unknown_key", "unknown_key / Direct JWKS (jwks) discovery procedure",
    extra={"discovery": {
        "jwks_url": f"{CLIENT}/keys.jwks",
        "jwks": {"keys": [dict(rq_jwk, kid="key-1", use="sig")]},
        "kid_presented": "rotated-away",
        "kids_available": ["key-1"]}})

# ---- JWT with no exp -------------------------------------------
_noexp = jws({"typ": "aa-token+jwt", "alg": "ES256", "kid": "issuer-1"},
             {"iss": ISSUER, "dwk": DWK, "sub": "instance-123",
              "iat": NOW - 60, "cnf": {"jwk": rq_jwk}}, is_sk, "ES256")
NEG.append({
    "name": "jwt-without-exp",
    "vector_category": 1, "now": NOW,
    "request": {"method": "GET", "target_uri": TARGET,
                "headers": signed_headers(f'sig=jwt;jwt="{_noexp}"', rq_sk, "Ed25519")[0]},
    "must_reject": True, "expected_signature_error": "invalid_jwt",
    "rule": "The jwt scheme requires exp. The assertion carries a "
            "confirmation key, and exp is what bounds how long that key is "
            "accepted; without it the key remains acceptable indefinitely. "
            "A missing required claim is rejected before any signature work.",
    "draft_section": "JWT Confirmation Key (jwt) / JWT requirements",
    "assertion_jwt": {"compact": _noexp, "missing_claim": "exp"}})

# ---- expired JWT, relative to now ------------------------------
_exp = jws({"typ": "aa-token+jwt", "alg": "ES256", "kid": "issuer-1"},
           {"iss": ISSUER, "dwk": DWK, "sub": "instance-123",
            "iat": NOW - 3600, "exp": NOW - 1, "cnf": {"jwk": rq_jwk}},
           is_sk, "ES256")
NEG.append({
    "name": "jwt-expired-one-second-before-now",
    "vector_category": 1, "now": NOW,
    "request": {"method": "GET", "target_uri": TARGET,
                "headers": signed_headers(f'sig=jwt;jwt="{_exp}"', rq_sk, "Ed25519")[0]},
    "must_reject": True, "expected_signature_error": "expired_jwt",
    "rule": f"exp is now - 1, so the assertion expired one second before the "
            f"instant this vector declares. Expiry is validated before the "
            f"signature, so a verifier fails here without cryptographic work. "
            f"Expressed relative to now ({NOW}) rather than as a fixed past "
            f"date, so the vector does not go stale.",
    "draft_section": "expired_jwt",
    "assertion_jwt": {"compact": _exp, "exp": NOW - 1, "exp_relative": "now - 1"}})

# ---- still valid, relative to now ------------------------------
_fresh = jws({"typ": "aa-token+jwt", "alg": "ES256", "kid": "issuer-1"},
             {"iss": ISSUER, "dwk": DWK, "sub": "instance-123",
              "iat": NOW - 60, "exp": NOW + 300, "cnf": {"jwk": rq_jwk}},
             is_sk, "ES256")
_fh = f'sig=jwt;jwt="{_fresh}"'
_fb, _ = signature_base("GET", TARGET, {"Signature-Key": _fh}, COMPONENTS, CREATED)
_fs = sign_base(_fb, rq_sk, "Ed25519")
NEG.append({
    "name": "jwt-exp-300s-after-now-MUST-ACCEPT",
    "vector_category": 1, "now": NOW,
    "request": {"method": "GET", "target_uri": TARGET,
                "headers": {"Signature-Input": f'sig=({" ".join(chr(34)+c+chr(34) for c in COMPONENTS)});created={CREATED}',
                            "Signature": f"sig=:{_fs}:",
                            "Signature-Key": _fh}},
    "signature_base": _fb,
    "signature_base_sha256": hashlib.sha256(_fb.encode()).hexdigest(),
    "signature_base_length": len(_fb.encode()),
    "must_reject": False,
    "expected_headers": {
        "Signature-Input": f'sig=({" ".join(chr(34)+c+chr(34) for c in COMPONENTS)});created={CREATED}',
        "Signature": f"sig=:{_fs}:", "Signature-Key": _fh},
    "key": {"public_jwk": rq_jwk, "private_jwk": rq_priv, "alg": "Ed25519"},
    "rule": f"exp is now + 300, so the assertion is live at the declared "
            f"instant and MUST be accepted. This is the positive control for "
            f"the expiry pair: without it a verifier that rejects every "
            f"assertion passes the expired case for the wrong reason.",
    "draft_section": "expired_jwt",
    "assertion_jwt": {"compact": _fresh, "exp_relative": "now + 300"}})

# ---- future-dated iat -> clock_skew ----------------------------
_fut = jws({"typ": "aa-token+jwt", "alg": "ES256", "kid": "issuer-1"},
           {"iss": ISSUER, "dwk": DWK, "sub": "instance-123",
            "iat": NOW + 3600, "exp": NOW + 7200, "cnf": {"jwk": rq_jwk}},
           is_sk, "ES256")
NEG.append({
    "name": "jwt-iat-one-hour-after-now-is-clock-skew",
    "vector_category": 1, "now": NOW,
    "request": {"method": "GET", "target_uri": TARGET,
                "headers": signed_headers(f'sig=jwt;jwt="{_fut}"', rq_sk, "Ed25519")[0]},
    "must_reject": True, "expected_signature_error": "clock_skew",
    "applies_to": "verifier_bounds_iat",
    "conditional": ("5.4.14 does not require a verifier to bound iat. This vector "
                    "applies only to a verifier that does. One that does not bound "
                    "iat is conformant and MUST NOT be failed for accepting this "
                    "request; it should skip the vector rather than record a miss."),
    "rule": "iat is now + 3600, further ahead of the verifier's clock than any "
            "reasonable validity window. The distinct code is what the caller "
            "needs: nothing about the assertion or the signature is wrong, the "
            "issuer's clock disagrees, and a fresh assertion from the same "
            "issuer carries the same skew. A future iat becomes acceptable "
            "with time, so the sender MAY wait and present the same assertion "
            "again. This is why clock_skew is not invalid_jwt or expired_jwt.",
    "draft_section": "clock_skew",
    "assertion_jwt": {"compact": _fut, "iat_relative": "now + 3600"}})

# ---- every signed negative publishes the key that signed it ----
for _v in NEG:
    _sf = _v["request"]["headers"].get("Signature")
    if not _sf:
        continue
    _km = {}
    for _part in _sf.split(", "):
        _lb, _, _raw = _part.partition("=")
        _rec = SIG_KEYS.get(_raw.strip(":"))
        if _rec is not None:
            _km[_lb] = _rec
    if not _km:
        raise SystemExit(f"{_v['name']} carries a signature made by an "
                         f"unregistered key, so the vector cannot publish it")
    _v["signing_keys"] = _km
    if len(_km) == 1:
        _v["signing_key"] = next(iter(_km.values()))

# ---- every signed negative publishes its base too --------------
# Three jwt cases were built as explicit dicts and discarded the base. Now that
# each one is a complete signed request the base exists, so publish it: a reader
# debugging a failure gets the same localisation everywhere, and the self-check
# below covers these vectors as well. A conforming verifier still rejects them
# on the assertion's claims before it needs the base, so the base is
# informational here rather than something to diff.
for _v in NEG:
    if _v.get("signature_base") is not None or _v.get("unsigned"):
        continue
    _hs = _v["request"]["headers"]
    if "Signature" not in _hs:
        continue
    _b, _p = signature_base("GET", _v["request"]["target_uri"],
                            {"Signature-Key": _hs["Signature-Key"]},
                            COMPONENTS, CREATED)
    _v["covered_components"] = COMPONENTS
    _v["signature_params"] = _p
    _v["signature_base"] = _b
    _v["signature_base_sha256"] = hashlib.sha256(_b.encode()).hexdigest()
    _v["signature_base_length"] = len(_b.encode())
    _v["signature_base_is_informational"] = True
    _v.setdefault("signature_is_reproducible", True)

# ================================================================ verify
def _verify_field(base, sigfield, keymap, fallback):
    """Verify every label in one Signature field against one base."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.exceptions import InvalidSignature
    results = []
    for part in sigfield.split(", "):
        label, _, raw = part.partition("=")
        jwk = keymap.get(label) or fallback
        if jwk is None:
            results.append((label, None))
            continue
        sig = base64.b64decode(raw.strip(":"))
        try:
            if jwk["alg"] == "ML-DSA-44":
                if not ML_DSA_44.verify(base64.urlsafe_b64decode(
                        jwk["pub"] + "=" * (-len(jwk["pub"]) % 4)), base, sig):
                    raise InvalidSignature()
            elif jwk["alg"] == "Ed25519":
                Ed25519PublicKey.from_public_bytes(
                    base64.urlsafe_b64decode(jwk["x"] + "==")).verify(sig, base)
            else:
                nums = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="), "big"),
                    int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=="), "big"),
                    ec.SECP256R1())
                der = encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                           int.from_bytes(sig[32:], "big"))
                nums.public_key().verify(der, base, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
            results.append((label, True))
        except InvalidSignature:
            results.append((label, False))
    return results

def verify_one(v):
    """The signature a signer is expected to PRODUCE, from expected_headers."""
    return _verify_field(
        v["signature_base"].encode(), v["expected_headers"]["Signature"],
        {lb: k["public_jwk"] for lb, k in (v.get("keys") or {}).items()},
        v["key"]["public_jwk"])

def verify_request(v):
    """The signature a verifier is GIVEN, from request.headers.

    Every must-reject vector is a complete signed request, so this is the check
    that the one fault in it is the one named and not a broken signature.
    """
    sigfield = v["request"]["headers"].get("Signature")
    if not sigfield or v.get("signature_base") is None:
        return []
    return _verify_field(
        v["signature_base"].encode(), sigfield,
        {lb: k["public_jwk"] for lb, k in (v.get("signing_keys") or {}).items()},
        None)

# ================================================================ output
import os
HERE = os.path.dirname(os.path.abspath(__file__))

bundle = {
    "description": "Spec-derived test vectors for draft-hardt-httpbis-signature-key. "
                   "Every vector publishes the RFC 9421 signature base verbatim.",
    "source_of_truth": "the draft text, not an implementation",
    "created_param": CREATED,
    "covered_components": COMPONENTS,
    "field_notes": {
        "key": "the key the vector's scheme member resolves to. On a positive "
               "vector it is also the signing key. Absent from a negative "
               "whose fault is that the member resolves to nothing usable.",
        "keys": "per-label key material, present only where labels resolve to "
                "different keys.",
        "signing_key": "the key that actually produced the Signature header. "
                       "On a negative this is deliberately not the key the "
                       "header names: the signature is sound so that an "
                       "end-to-end verifier reaches the rule under test "
                       "instead of stopping at invalid_signature.",
        "signing_keys": "the same thing per label.",
        "unsigned": "true on the two vectors that cannot carry a signature at "
                    "all, with unsigned_reason giving the reason.",
        "signature_base_is_informational": "the request is signed and the base "
                                           "is real, but a conforming verifier "
                                           "rejects on the assertion's claims "
                                           "before it needs the base, so do "
                                           "not treat the base as the thing "
                                           "under test.",
        "applies_to": "a precondition on the verifier, not on the request. "
                      "verifier_bounds_iat means the vector is a must-reject "
                      "only for a verifier that bounds iat.",
    },
    "positive_vectors": VECTORS,
    "negative_vectors": NEG,
}
with open(os.path.join(HERE, "signature-key-vectors.json"), "w") as f:
    json.dump(bundle, f, indent=2, sort_keys=False)
    f.write("\n")

# ---- self-check --------------------------------------------------
ok = fail = 0
print("self-verification, every signature against its own published base")
for v in VECTORS:
    for label, good in verify_one(v):
        tag = "ok " if good else "FAIL"
        print(f"  [{tag}] {v['name']:<44} {label}")
        ok += good; fail += (not good)
for e in NEG:
    if e.get("must_reject") is False and "expected_headers" in e:
        for label, good in verify_one(e):
            tag = "ok " if good else "FAIL"
            print(f"  [{tag}] {e['name']:<44} {label}")
            ok += good; fail += (not good)
print(f"  {ok} verified, {fail} failed")

req_ok = req_fail = req_skip = 0
print("verification of the signatures the must-reject requests actually carry")
for e in NEG:
    for label, good in verify_request(e):
        if good is None:
            req_skip += 1
            print(f"  [SKIP] {e['name']:<44} {label}  no signing key published")
            continue
        tag = "ok " if good else "FAIL"
        print(f"  [{tag}] {e['name']:<44} {label}")
        req_ok += good; req_fail += (not good)
print(f"  {req_ok} verified, {req_fail} failed, {req_skip} without a key")
if req_fail or req_skip:
    raise SystemExit("a must-reject vector carries a signature that does not "
                     "verify, so it would fail for the wrong reason")

# ---- markdown appendix, RFC 8792 wrapped -------------------------
md = ["# Test Vectors",
      "",
      "Vectors for the Signature-Key schemes, derived from the draft text "
      "rather than from any implementation. Each publishes the signature base "
      "verbatim, so a signer can be checked without a live verifier.",
      "",
      "Long lines use RFC 8792 single-backslash line folding; a line ending in "
      "`\\` continues on the next line with no inserted whitespace.",
      "",
      f"All vectors use `created={CREATED}` and cover "
      f"`{' '.join(COMPONENTS)}`. Keys are derived from fixed seeds, so every "
      "value below is reproducible by rerunning the generator.",
      "",
      "## A note on which signatures reproduce",
      "",
      "Ed25519 is deterministic (RFC 8032), so an Ed25519 vector's `Signature` "
      "value is reproducible byte for byte and can be compared directly. "
      "ECDSA is randomised: each `ES256` signature below is one valid "
      "signature among many. For those, compare the **signature base** and "
      "then verify the signature. A conformance suite that diffs ECDSA "
      "signature bytes will report false failures.",
      ""]

for i, v in enumerate(VECTORS, 1):
    md += [f"## A.{i} {v['name']} (`{v['scheme']}`)", "",
           v["notes"], "",
           f"Category **{v['vector_category']}** "
           f"({ {1:'key handling, nothing signed',2:'verify only',3:'reproduce the bytes'}[v['vector_category']] })"
           + (f", **{v['conformance']}**" if v.get('conformance') else "")
           + f". Evaluate at `now = {v['now']}`.", "",
           "Request:", "", "~~~ http-message",
           wrap8792(f"{v['request']['method']} {v['request']['target_uri']}"),
           wrap8792(f"Signature-Key: {v['request']['headers']['Signature-Key']}"),
           "~~~", "",
           f"Signature base ({v['signature_base_length']} bytes, "
           f"SHA-256 `{v['signature_base_sha256']}`):", "",
           "~~~", "NOTE: '\\' line wrapping per RFC 8792", "",
           wrap8792(v["signature_base"]), "~~~", "",
           "Expected headers:", "", "~~~ http-message"]
    for k, val in v["expected_headers"].items():
        md.append(wrap8792(f"{k}: {val}"))
    md += ["~~~", "", "Key material (private key included so the vector can be "
           "regenerated):", "", "~~~ json",
           json.dumps(v["key"], indent=2), "~~~", ""]
    for extra_key, title in (("delegation_jwt", "Delegation JWT"),
                             ("assertion_jwt", "Assertion JWT"),
                             ("discovery", "Discovery documents")):
        if extra_key in v:
            md += [f"{title}:", "", "~~~ json",
                   json.dumps(v[extra_key], indent=2), "~~~", ""]

md += ["## A.{} Negative vectors".format(len(VECTORS) + 1), "",
       "Each of these is derived from a MUST or MUST NOT in the draft and "
       "names the section it comes from. A verifier that accepts a "
       "`must_reject` vector, or rejects the one marked MUST-ACCEPT, is "
       "non-conformant.", ""]
for j, e in enumerate(NEG, 1):
    verdict = "MUST REJECT" if e.get("must_reject") else "MUST ACCEPT"
    md += [f"### A.{len(VECTORS)+1}.{j} {e['name']}", "",
           f"**{verdict}**" + (f" with `error={e['expected_signature_error']}`"
                               if e.get("expected_signature_error") else "")
           + (", plus `" + ", ".join(f"{k}={v2}" for k, v2 in
              e["expected_signature_error_members"].items()) + "`"
              if e.get("expected_signature_error_members") else "")
           + (f" (category {e['vector_category']})" if e.get("vector_category") else ""), "",
           f"Section: {e['draft_section']}", "",
           e["rule"], "", "~~~ http-message"]
    for k, val in e["request"]["headers"].items():
        md.append(wrap8792(f"{k}: {val}"))
    md += ["~~~", ""]
    if "discovery" in e:
        md += ["Served at the discovery URL:", "", "~~~ json",
               json.dumps(e["discovery"], indent=2), "~~~", ""]

with open(os.path.join(HERE, "test-vectors-appendix.md"), "w") as f:
    f.write("\n".join(md) + "\n")

print(f"\n{len(VECTORS)} positive, {len(NEG)} negative")
print("wrote signature-key-vectors.json and test-vectors-appendix.md")
if fail:
    raise SystemExit(f"{fail} signature(s) failed self-verification")

# ---- emit the discovery documents as files an implementer can serve ----
served = {}
for v in VECTORS + NEG:
    d = v.get("discovery")
    if not d:
        continue
    if "metadata_url" in d:
        u = d["metadata_url"].split("://", 1)[1]
        served[u] = d["metadata_document"]
    if "jwks" in d:
        ju = d.get("jwks_url") or d["metadata_document"]["jwks_uri"]
        served[ju.split("://", 1)[1]] = d["jwks"]

collisions = {}
for v in VECTORS + NEG:
    d = v.get("discovery") or {}
    for u in ([d["metadata_url"]] if "metadata_url" in d else []):
        collisions.setdefault(u.split("://", 1)[1], set()).add(
            json.dumps(d["metadata_document"], sort_keys=True))
    if "jwks" in d:
        ju = d.get("jwks_url") or d["metadata_document"]["jwks_uri"]
        collisions.setdefault(ju.split("://", 1)[1], set()).add(
            json.dumps(d["jwks"], sort_keys=True))
bad = {k: v for k, v in collisions.items() if len(v) > 1}
if bad:
    raise SystemExit(f"two vectors claim one discovery path with different "
                     f"documents, the served tree cannot represent both: "
                     f"{sorted(bad)}")

for rel, doc in served.items():
    p = os.path.join(HERE, "served", rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
print(f"wrote {len(served)} discovery document(s) under served/")
for rel in sorted(served):
    print(f"  served/{rel}")

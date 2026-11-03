# Signature-Key test vectors

Generated from `signature-key-vectors.json`, which is authoritative; this file
folds long lines per RFC 8792. Every vector is evaluated at `now` = 1800000000.

## Keys

### agent-ed25519 (Ed25519)

Seed = SHA-256("aauth-conformance signature-key vectors agent-ed25519").

```
{
  "alg": "Ed25519",
  "crv": "Ed25519",
  "d": "b1pgo1eL_yXGlZJ9nXX2k-3yC0VK5IZAu9Ddz-qEeZ8",
  "kty": "OKP",
  "x": "ge9CgQnrIEclu2brzev1Ve02hk2_S65Fk_2JSD-dIsA"
}
```

### agent-es256 (ES256)

Private scalar d = SHA-256("aauth-conformance signature-key vectors agent-es256").

```
{
  "alg": "ES256",
  "crv": "P-256",
  "d": "tASMl1c_U2KQBJZODumNtXKlq8VuOf65JFlCISF66UE",
  "kty": "EC",
  "x": "kWn1q9uoMexzm15PKmMJ9n45OYzIJOFhsGAfNvxLaG8",
  "y": "SFtVwCFSswQbnzphZWuRiu78r8L21Y_mFpYLaUzTuXw"
}
```

### agent-es384 (ES384)

Private scalar d = SHA-384("aauth-conformance signature-key vectors agent-es384").

```
NOTE: '\' line wrapping per RFC 8792

{
  "alg": "ES384",
  "crv": "P-384",
  "d": "7iAx_04y-mivOgA6wCAJ252aW-MfFGj8T0VZKhIOHUWYaug9k4t160lwAoB\
940PD",
  "kty": "EC",
  "x": "bfPOJCwtKpeY-u4uoaDBCfsct3meT5xE2xcLJtxuqWnW_Bgn1nXi-DNsuFv\
bf2Au",
  "y": "O6DNv-okgDuYtZ4keVM0oizSEw8SKem9lLja7W7fy0ykCtGkdNmXvD0daJd\
zxelI"
}
```

### agent-rs256 (RS256)

The aauth-conformance fixture's RS256 test key (fixture.json extensions.sigkey.keys).

```
NOTE: '\' line wrapping per RFC 8792

{
  "alg": "RS256",
  "d": "C27NkMrOwemD-_BaTIXAM0n1zB05UXuQmVepHfq14ZhySgRumYmGmKbm6IY\
Al5dyVpy25YD-M8D4IvIKaRMXLsYpmrtIt1wRgu2OoTZ-IVRGPI1kAehDpD8ooQPBBQ\
pwEPlL-AOM5dEeNQYwvP0Bzmecrc2ctnF6ANuUCP6vzOzG4NE6Wwcuu9tBMXtfsWLBC\
BGejwOIQOHccwzvoXdjbwdAEeWJwJBf-fPgM6sKgwYTvbISN1xvchPSS1T03oe_bZ-C\
N9JynYNZpZlTAkVUxToFKzxJu9cISdFRYQUa-N7zsz7s_KzpAC6K2JICeGUBvmyWApE\
76CJML9p1PpHpHQ",
  "dp": "eJp4OxeKCRmixZjDFa-DYhjG8D03rV6Z_PdpSyIyB9kpGGB-EPtPsPxFvr\
OWvBFh8P53rpzAZYd6m66KdNFyEx6zNQtoxC0tirIPIbcFhXGpNyhg1l2ShVQ9kuYy7\
M9tYxYw8Jm-FLg7h8SGx0aep-GkmDTeO36FOwf1z9ivFIs",
  "dq": "cVEEnahre5f6uygIrr5QfmdQOvaTFRZ1ReSOR3tpTMJym_FM0OiJhnB7r0\
JmDFFthVIohGsCh2ZeuFeppGWFMfWFTc0PXvcaijWqPeLwn51K-gvR1SiHLAow_oKe6\
zl6LZYuMsL4Yh0PCFqlHuoK5acFL_PrYXGFuzwrvpVJQS0",
  "e": "AQAB",
  "kty": "RSA",
  "n": "1KFNkiisqhCg_0L8nOANDip7MUTjx3JwWxI7U8-z-9vQFf38iO066yApzbi\
SL-DBll-X722d6BZFUwmgpUM0xOCbb2XZU0aFF1ZPaXUriiVJDzFVGtCWqTUPeXvCNb\
6TdQzqQ7KGw8m1mCqN96zmWUpvIidXEqXjYG8rCYh0ZxBssTn5HWWEOZ4G5hZ4AwiXS\
KarZ6gr50wunF8TwtC8s8BoB9u-Wd_LWoApo3MzAGHWqNzwPHW0InAESJnn2rgsiNO6\
tElYOpKbxKlEJHad66oH26iuXzwkBSnA6kfosMqQq_rcQ2bw12ZfhwZfTJHKnfhE6rE\
R5FLKS1DmUwx9Gw",
  "p": "886jE8NtGLzKfpQxa6SxLlCZ1XhZ-oGUBLepSKcR2sTeqi8xkBWcRKsoIV2\
kMP3QDgcQnXYySayg9S7N5Be2cJB2irNoyuUYE2QSggLKE-ilpUfV2pLF9Y0IVwTOwc\
D8lbdeA-wO_cygbWpxUJB1vgi8xmfkJMXErVsL7iRM0-8",
  "q": "30OEwfQEnitBX3Zb9ez0IVawB89oAxchRgbZ2ZvY36aYexu8QmH96gUE1sW\
acil3UhABxko61Uzswdcl81s4ash7OhoJprovANsZmhhyemZ81-K4-puTBo9brOCt-u\
CaObWLgGfE_ls9cy_nsR9cWEZ1NLB0SQdjxa1ZlROODZU",
  "qi": "wCWz2N4zjzkgrUKWwCy5RGnBaZMOmeCMOVXQghnZMSBp8bXpGyXvx0elOo\
lPQhLc0KqH_t0c5bjfyFkfp-PUeP5RjR5Ud81w1OPFqn5_c4ssWUF3WZi8IWeSRt0eS\
dLrWedqXBnsD5KD83cZ1wowilWege8dVZQTSzRfSVUAOqw"
}
```

### agent-ps256 (PS256)

The aauth-conformance fixture's PS256 test key (fixture.json extensions.sigkey.keys).

```
NOTE: '\' line wrapping per RFC 8792

{
  "alg": "PS256",
  "d": "CbijyMA53ksSNySvjlUYDJ2ErnNyh8JYfJwOUvO8qJ8LTIjWomH3MMuCQD4\
hDQQBacwKSHxuzlyzMXMBtPZYZGOTejQBHqTZutcIUybMAP1XzEO87BS_NirgwP0BGZ\
ko-3cw34ot7AVQIzNbnQHM3Bs-8oXVSWsAaO0hpecRAyUqXe2676n53fUOvU4hXk9cF\
IFvBm6xpQvrURdLW8w9JrLVmua5junBLIiboL39eHt6WmwKJ3dwoLhl-rsPRGLq9wmr\
gf0DD2rfbHT2biqvtivF0T7tpS-USROBCxbeLxTwNaSkb4zW_OaWpFMy2pYK8GY6lr2\
RwZSr20YKaS6mgw",
  "dp": "jBTiBLH_aaH6PULLEHJ_W0I3hwGVkFVMfE46e5rlsJxKUu5CfOGn76-hcg\
e7G77lNwIGySrLWsysSzqM4TIz_HKv_p1l0WqQONa004Ll-S46VvSl2z7IcEphyjxI4\
R9KJhWt4VrW4f2LrptRgfO2rChkFS-OmRNhzL5GL7awI3M",
  "dq": "ChuqqQ_kOs19MDt2Ahp3kBOvtzxS6f0cjd1Fr0tdRlogIRaDGc-aWAI5RD\
-AEcB6e8N3lqX93gYEIEHXncw5n_ACBP9a_m-UAS_0q5WR4lSXvAptLkdIXDnf7PdLe\
tuhoTDG1dFORB9n5sbL5zUy2eFkMOakpFtm9KSCLT31Nt8",
  "e": "AQAB",
  "kty": "RSA",
  "n": "tE2hQ7RoXWIGUZIlGG0i748Sp0uG87X5ee96CqeMG11F2NCYFlueGn6lGB3\
xYC5A-QqeoUB3BP_b7lY54oRRfICD_KE5LF-D8bXS4JocdQfq9hO4QxBuVZG57oWs8b\
XICrws-Lj_Lmu-ZeZW5K4ooynqdzxfbx8_2-MP1SlmD3N_mOPzHiaVDSxelry0xH61Y\
Lh_0nUHrKw37wiIqwQZgsKDnTBMN1YMmNsdIt5AUdKlyWJzQBN9S0TCAKE47vJxZoqV\
TDBxc-w2jG1zif-2h_mwbzLnWQj0FebK_sI5jagVDEGn5_Zzzw3rXFhjYDhraWkqMGb\
mZdq0sd8Iw9jF5Q",
  "p": "3p4ZRnOTb-pFrt8ep7rR6yoMu8DIvp6WX424iSZA94a-iOiZeWe61Fz_pOD\
GqyJj9-zd1XypDvReCKvUi160v3ZqONvhRuA4b9ThDk6cfzwOgjHA8PzNEoXQZAG7j_\
0wiMRvzrC8MsHHLO5zlUjWyULAyMFbSdQHrGt2GgpkC18",
  "q": "z1coXII6EPbI7oEuW4qCfMZflUbDNcQcHzwjTOyTP1S7HAPcc0bDUGk59-O\
AOHO4Oiq8JKnoH7hhSzwp9O4V96M2KkGKrhPoBhYaZ4p-bfhQLQsTNNbya2L3fnSJqt\
X5LNKSMitvP4NTvtWCCyVDT752m9SJGB8Ik7U6jTD-OTs",
  "qi": "QRUwX17yz7axPkGgbtxXswliIfnlCYikkK_3aJbni7Znyam-o4uKPFFKYy\
q8qa42Jb1VFKTNK_mSMNAuSuiNNMB2OcB7CKU0aNPYRt_z8E-1UO4mauMqgp3uUYL3-\
0W3QV3TewhuaxlkFZboIbqaWcdT6tlOH5_Igl7bI5VOD3w"
}
```

### other-ed25519 (Ed25519)

Seed = SHA-256("aauth-conformance signature-key vectors other-ed25519").

```
{
  "alg": "Ed25519",
  "crv": "Ed25519",
  "d": "lT6tzEScuuATe_YNoJ5uTZ2PsyD19niFAjAmWxZdQYE",
  "kty": "OKP",
  "x": "zzWQXOdUngYs5QBLDKqNR9kqbk80wnBqGZN-zD1A3RQ"
}
```

### ap-ed25519 (Ed25519)

Seed = SHA-256("aauth-conformance signature-key vectors ap-ed25519").

```
{
  "alg": "Ed25519",
  "crv": "Ed25519",
  "d": "yL52Ln25HNuLxXvCHSw8_ZP9tzsCMyCEYkjz64coME4",
  "kid": "ap-ed25519",
  "kty": "OKP",
  "x": "9YIWN80tEjjl15PYCUMALnmQnFwualkJxWB9xKHb_tc"
}
```

### signer-ed25519 (Ed25519)

Seed = SHA-256("aauth-conformance signature-key vectors signer-ed25519").

```
{
  "alg": "Ed25519",
  "crv": "Ed25519",
  "d": "59x5alpJDaRY1oAVglJVoaTR172YF8AmPw9grJt52Ck",
  "kid": "signer-ed25519",
  "kty": "OKP",
  "x": "G655YZ6vyw20ekWtwpnVOuwF36y6CsxxmluRvwZamO4"
}
```

### signer-es256 (ES256)

Private scalar d = SHA-256("aauth-conformance signature-key vectors signer-es256").

```
{
  "alg": "ES256",
  "crv": "P-256",
  "d": "yG8mh32bhCdpQqJkHNUCUIbcNcsKCrMmSsHhwOJbsNY",
  "kid": "signer-es256",
  "kty": "EC",
  "x": "na6GJ2V2n70jCjzJF7H5rtXnUokY_90isxO3ny4iNLQ",
  "y": "5vt7nLlc92fzNn5baKytoofmPBukg5ikncT8hIWSQJs"
}
```

### signer-ml-dsa-44 (ML-DSA-44)

FIPS 204 seed xi = SHA-256("aauth-conformance signature-key vectors signer-ml-dsa-44").

```
NOTE: '\' line wrapping per RFC 8792

{
  "alg": "ML-DSA-44",
  "kid": "signer-ml-dsa-44",
  "kty": "AKP",
  "pub": "vCWs7y8_K8ndKqvKsVninhAQnDuW8EK2hyhvbXRxohfBAtkRpeDnm26tu\
J6yUmNRB_A7jgh46286BdSD17QWQzCd3Ntt6uVVQxeL4F2y89pkMMljKcn3_S9aWxS_\
9hQHo3amelEVlYoCJycvpNlpCaGo_a275c9nWjtvjotRTnq8ur8ZHppmsQDQnUcLoVB\
Dwnn27sUNQZ6ChGqSZBuCozEH1LRhdxDXfmYg7mvFi8FWE68ci9P5BvwDIBukfSrelv\
WYy9jSi-VPkrXohFD1Ljk_U9FAkW7u6bVmToWWyXHRv-Z4ZPKSpe_1pIZNffIoXoQ0V\
gqrFb5g1AFcCL_jefp55D26cp-HGF4pE0zPtpUf-DHba-rUFkg4cfYJRwszgoD5JHMz\
BTl1xqLekeVpIgh135-Im0nvjJo_C6JYD-frkfiH3eh6QkJ9hkbRA7Ooy8G6ncGTB5L\
a2mRFNavXtawiCHLKxfk9EShjh7VeV3iriCj0A4RQlAvaQlJIZELHISJJq1BvgCwRJ4\
kUjah3ksdOqXocg3nXIAExjO0S96KsvepJsx1v0Aoc0Dd33jrKmLS7PuoUmjDhQXoKr\
ZidNIHLb_yKV84OSjJELtW76IbaJq3gNF9xMmSOhfX50I40N_clO2pG9WttRBHX_pfF\
wBw53ficYR8RVbycVYnaPc3WZhJtwkWOAVjld5jA84TOY49j-Xunoa7ZK5IvvGOOXi5\
QI_DXTiV_7c6PjvJOhMA1eOlXS8BvWcwZigCOCYKTyiqARb920hkgcSzzjDvS2ABeum\
g0LnNC6TRcZEL574zgX0O02Ij8xhvcUC8I__DrR0jOg_MVXxLqfYS6qXYNrJ01IUstF\
fJm-r-CFcYfWkB5I-MHik9DlF0Wu5iJvFZAD1DbjUWAq-AI-a4RZM29BFIud9B7GzKu\
LGFZRNv4NeshL0nSzsSG1ELOHXkMGsiuicfFnDlDlo2iR59zxVqno8su9E3mqILIXZe\
TzRw0L1_o1FO07QyXVCoEdAcVYjFPBbB6hTxHk9pEZc1J3gY4GsI8XIEhd5O8UIp5ji\
lGY03sktuvWVA_LHzOThx2rP2Hu57dNHcywliVbfjNPQY_6u1pOPPToulQdOwnTfzs2\
6wd96Z4SH_posjyWxFb6u8EfxkMlIZ3AM1dKNk3xb7CIXWvOjNSZg3fJoC4a_cjOO0a\
-C3RqbZDcZ-02tDeGSVbZehzzN8lm0-t0zD3-ThMF5odJCkgg1fbBbjRxNsGKUHZHV9\
NStJiKUGNVeX3rF_Vbu2xdjqt16uRx86c8PWafK0AVb1zcyBZSQk8R3gj8jgrkx9G4L\
ZmuxbAXqIx5cw2TWtgeSBV_zf8eCeU5JsGTda8Wra-LE31BGoRtdq64W3vInZnuhxKb\
3mcjleE-1PJDSsFGLCY5ukelsP-U8Kd1OB9rukXGcqFyOnvvD7v7tq-41HmW4nU9-GT\
D23JX9fnjT-bo5m3nCYmaiFMpLXygS9Le_NPeaQ8cvbY7v-Y3bx_CLV7jSA9qzKCOXv\
QifWGvyFLwKJrs2L5zf7LMj79eGE9gIDr9AFfhNYf3WbAT0VlgDX8fFRz6PQTfz9dRH\
5tCDK5SYehbCl4dxwvhJZ922rjo5y99TL4WBV1AaKXw2Fs_voFm1C6yFmnMmn6L5UPG\
txp4R5Cb8yJrvypgCyH-QvQs8pvsoZKgl9d0QPFJa4OlnBVnus7vIXse1MCls-Gd2md\
1eEyKlaJUay4RqDjaw",
  "seed_hex": "aec541c1e8e3c4d293142f04fc8f784892d23bb89d85fc14639b\
a50d8114805c"
}
```

### jkt-identity-ed25519 (Ed25519)

Seed = SHA-256("aauth-conformance signature-key vectors jkt-identity-ed25519").

```
{
  "alg": "Ed25519",
  "crv": "Ed25519",
  "d": "9Alky8faF-p4bhARtJAGphSNiu6pBxgwJPMeS-CUG90",
  "kty": "OKP",
  "x": "xMhCrtHXUGjauU2ci3cct0HCofsRTWJmD3kCDC8HQ5A"
}
```

### jkt-identity-es256 (ES256)

Private scalar d = SHA-256("aauth-conformance signature-key vectors jkt-identity-es256").

```
{
  "alg": "ES256",
  "crv": "P-256",
  "d": "rjiViZoYyR54XlwAwgCvHHQlrttOkz5NYOlmnQv2xy8",
  "kty": "EC",
  "x": "ldfzNpUwk0U-aTaxPVmIzGiVP5bu1FSHmS1WvnVmBFo",
  "y": "qQwmBCtAfAYER9jST7jqkcrLR2j3BEb8cfUGuedgLYo"
}
```

### ca-ed25519 (Ed25519)

Seed = SHA-256("aauth-conformance signature-key vectors ca-ed25519").

```
{
  "alg": "Ed25519",
  "crv": "Ed25519",
  "d": "lR0eVYldU4cC0g-3VkmbSdmaTE4bLudtloahL7AyTOs",
  "kty": "OKP",
  "x": "LV9LyDIgV27YSN6Y7uyWMndAfdEp9813f4yUXDi9AR4"
}
```

### x509-ed25519 (Ed25519)

Seed = SHA-256("aauth-conformance signature-key vectors x509-ed25519").

```
{
  "alg": "Ed25519",
  "crv": "Ed25519",
  "d": "RqCC_perLs5ceUmFN8l08hctrq5TvpYf1OTgShaxr0k",
  "kty": "OKP",
  "x": "KKQdda7UZqrlAZrhhTUzu_XDIxHwT_cqtXd79PKEjl4"
}
```

### x509-es256 (ES256)

Private scalar d = SHA-256("aauth-conformance signature-key vectors x509-es256").

```
{
  "alg": "ES256",
  "crv": "P-256",
  "d": "bGlRThT26JmKRcvd6rBBbecNAv3ZHMVA4RQoYEjZHsE",
  "kty": "EC",
  "x": "ooQulrtbZieXmZUQYIAUasssFpxOfc_YLagzXnXWtyQ",
  "y": "b1Lunq_EQlCKQJk1FEzSe29YgiknOQmrY4IAGz1Fdc0"
}
```

## Vectors

### hwk-ed25519

hwk, Ed25519, GET. Category 3 (reproduce-the-bytes). Signed by aauth-rust; aauth-go produced the same bytes. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:wGI92boz47sJN4qsSaCcM0+BMgWEO811RefzvZKQsWWi1JyUrAa\
eest2kFd5oYfb9Vi8G3wYD+rV6AliCGTCBQ==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2brz\
ev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"

```

Signature base (265 bytes, SHA-256 e09cd5dec4a12dd98550210595214918f0203dc9156a5cbdce50906ca01f273f):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2b\
rzev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### hwk-ed25519-post

hwk, Ed25519, POST with query, Content-Type and Content-Digest. Category 3 (reproduce-the-bytes). Signed by aauth-rust; aauth-go produced the same bytes. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

POST /api/items?page=2&sort=name HTTP/1.1
Host: resource.example
Content-Digest: sha-256=:yWRQMvfPuwvj3bhaB0ZKxQISjqgfP1D8MGSsslsPmw\
g=:
Content-Type: application/json
Signature: sig=:GiTTTOfV+HD0YmA6hdgJiSfGBRNiidwLOvfl1MjqB68HmAJZH8g\
qF619rasIhXXwjHleGVeVosID0JxVRd6gBQ==:
Signature-Input: sig=("@method" "@authority" "@path" "@query" "cont\
ent-digest" "content-type" "signature-key");created=1800000000
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2brz\
ev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"

{"name":"widget","quantity":3}

```

Signature base (441 bytes, SHA-256 cb9e1d11621912eaab9d5f2b87aa692ce187a57ce4c88f8b0ab8f4d7fefa6773):

```
NOTE: '\' line wrapping per RFC 8792

"@method": POST
"@authority": resource.example
"@path": /api/items
"@query": ?page=2&sort=name
"content-digest": sha-256=:yWRQMvfPuwvj3bhaB0ZKxQISjqgfP1D8MGSsslsP\
mwg=:
"content-type": application/json
"signature-key": sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2b\
rzev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"
"@signature-params": ("@method" "@authority" "@path" "@query" "cont\
ent-digest" "content-type" "signature-key");created=1800000000
```

### hwk-ed25519-nonce

hwk, Ed25519, with a nonce signature parameter. Category 3 (reproduce-the-bytes). Signed by aauth-go. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:bkFmAEM9K5rkt3oY6NiQrxOmECKz16aB4pQNhRV3W5t3m7bFk2J\
RhfDzlw/KKa9ay4kwOIWVxhnYqwQslQpKBQ==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000;nonce="n-0001"
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2brz\
ev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"

```

Signature base (280 bytes, SHA-256 d202de1c667dfa357fcc841f85f05e943de15db81b09f303529365751e7c8b5e):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2b\
rzev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000;nonce="n-0001"
```

### hwk-es256.rust

hwk, ES256. Category 2 (verify-only). Signed by aauth-rust. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:J1vmn42cYsRiFuOXPJxHUAWZPmEk1tpyFKETvccoMwU/zsojzgG\
NgScoz3m2EMkSSjo2WsUOeDDlXkhpAuBZCA==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="EC";crv="P-256";x="kWn1q9uoMexzm15PKmMJ\
9n45OYzIJOFhsGAfNvxLaG8";y="SFtVwCFSswQbnzphZWuRiu78r8L21Y_mFpYLaUz\
TuXw";alg="ES256"

```

Signature base (308 bytes, SHA-256 8fc727b8753f44f8502bf77019b82713b8293ca1a58d42b77c9804e8d5fc276b):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="EC";crv="P-256";x="kWn1q9uoMexzm15PKm\
MJ9n45OYzIJOFhsGAfNvxLaG8";y="SFtVwCFSswQbnzphZWuRiu78r8L21Y_mFpYLa\
UzTuXw";alg="ES256"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### hwk-es256.go

hwk, ES256. Category 2 (verify-only). Signed by aauth-go. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:GlrC9sWAA+TBvgVtfR7uotxNZ8rMkrFiimQrEit8yos/WRtcT6b\
kwdu+aRORiQUOXTs0YJ7pEeU2wTUet80Tzg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="EC";crv="P-256";x="kWn1q9uoMexzm15PKmMJ\
9n45OYzIJOFhsGAfNvxLaG8";y="SFtVwCFSswQbnzphZWuRiu78r8L21Y_mFpYLaUz\
TuXw";alg="ES256"

```

Signature base (308 bytes, SHA-256 8fc727b8753f44f8502bf77019b82713b8293ca1a58d42b77c9804e8d5fc276b):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="EC";crv="P-256";x="kWn1q9uoMexzm15PKm\
MJ9n45OYzIJOFhsGAfNvxLaG8";y="SFtVwCFSswQbnzphZWuRiu78r8L21Y_mFpYLa\
UzTuXw";alg="ES256"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### hwk-es384.rust

hwk, ES384. Category 2 (verify-only). Signed by aauth-rust. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:IJgX4cjyosiSu7YsyFfXxRoiCjbkgTtYcpTKVMgs+gHQu0FIdWT\
j7XbUbU0HhhxbYRbaOS38JHJJixeRod6Hc1uH9C/+GMN9V4y6j76YEcTUkNGuUqD9yz\
wTw4q15o6/:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="EC";crv="P-384";x="bfPOJCwtKpeY-u4uoaDB\
Cfsct3meT5xE2xcLJtxuqWnW_Bgn1nXi-DNsuFvbf2Au";y="O6DNv-okgDuYtZ4keV\
M0oizSEw8SKem9lLja7W7fy0ykCtGkdNmXvD0daJdzxelI";alg="ES384"

```

Signature base (350 bytes, SHA-256 f8f5e72b919c4e66a6ae0f955b52f679c4a70ba81e53ccbda70ce0001c79458d):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="EC";crv="P-384";x="bfPOJCwtKpeY-u4uoa\
DBCfsct3meT5xE2xcLJtxuqWnW_Bgn1nXi-DNsuFvbf2Au";y="O6DNv-okgDuYtZ4k\
eVM0oizSEw8SKem9lLja7W7fy0ykCtGkdNmXvD0daJdzxelI";alg="ES384"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### hwk-es384.go

hwk, ES384. Category 2 (verify-only). Signed by aauth-go. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:U+2G+ZKgnQmEu5w6+jwp6UVkg2Swf7oiJMXLgDvn2dQTnPQqjHg\
hdOWWbmsV7F6YdCrgGULSZjgzPvqB8YT/sS/ltDOjDbATS+eQkayMS8CL/DjiQ5QCNf\
KR2WGwtMEr:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="EC";crv="P-384";x="bfPOJCwtKpeY-u4uoaDB\
Cfsct3meT5xE2xcLJtxuqWnW_Bgn1nXi-DNsuFvbf2Au";y="O6DNv-okgDuYtZ4keV\
M0oizSEw8SKem9lLja7W7fy0ykCtGkdNmXvD0daJdzxelI";alg="ES384"

```

Signature base (350 bytes, SHA-256 f8f5e72b919c4e66a6ae0f955b52f679c4a70ba81e53ccbda70ce0001c79458d):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="EC";crv="P-384";x="bfPOJCwtKpeY-u4uoa\
DBCfsct3meT5xE2xcLJtxuqWnW_Bgn1nXi-DNsuFvbf2Au";y="O6DNv-okgDuYtZ4k\
eVM0oizSEw8SKem9lLja7W7fy0ykCtGkdNmXvD0daJdzxelI";alg="ES384"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### hwk-rs256

hwk, RS256. Category 3 (reproduce-the-bytes). Signed by aauth-rust; aauth-go produced the same bytes. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:aWMqDuIB+aGUlkFFz33ErleHwB/tiyflbgu1nAaqvraZ+jT4ZAN\
jPVjZUBTf4sPFvex9aP7UFGkwJZWlN4EIlo0KgX2/ng5gGjy+kEH5bRztT0JUF0Au+Z\
lIjfQ3KWIX4CzOvkLXS/W2mkbXV1vYfYEt+8XJtRilGF9JvaPhW49SROqG1K+mrauv9\
qohUnOWfnp9f2Gq4nUqtvDKo55iejVc7HEukmgrNEqI7FDDa7CEyuiKm0ECS9XtlhVn\
1CN9GHy/xGkbBGh6dfoD4jRAjZU0fST7LsCLgD6igTfFruVUI/8iAFC9ISo8iayRK6O\
J4imesvOPLS2Y7wn6D47iQQ==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="RSA";n="1KFNkiisqhCg_0L8nOANDip7MUTjx3J\
wWxI7U8-z-9vQFf38iO066yApzbiSL-DBll-X722d6BZFUwmgpUM0xOCbb2XZU0aFF1\
ZPaXUriiVJDzFVGtCWqTUPeXvCNb6TdQzqQ7KGw8m1mCqN96zmWUpvIidXEqXjYG8rC\
Yh0ZxBssTn5HWWEOZ4G5hZ4AwiXSKarZ6gr50wunF8TwtC8s8BoB9u-Wd_LWoApo3Mz\
AGHWqNzwPHW0InAESJnn2rgsiNO6tElYOpKbxKlEJHad66oH26iuXzwkBSnA6kfosMq\
Qq_rcQ2bw12ZfhwZfTJHKnfhE6rER5FLKS1DmUwx9Gw";e="AQAB";alg="RS256"

```

Signature base (557 bytes, SHA-256 7914575883313601dca932c616b6480692952c20a2535d6cf508cbb1caa135c9):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="RSA";n="1KFNkiisqhCg_0L8nOANDip7MUTjx\
3JwWxI7U8-z-9vQFf38iO066yApzbiSL-DBll-X722d6BZFUwmgpUM0xOCbb2XZU0aF\
F1ZPaXUriiVJDzFVGtCWqTUPeXvCNb6TdQzqQ7KGw8m1mCqN96zmWUpvIidXEqXjYG8\
rCYh0ZxBssTn5HWWEOZ4G5hZ4AwiXSKarZ6gr50wunF8TwtC8s8BoB9u-Wd_LWoApo3\
MzAGHWqNzwPHW0InAESJnn2rgsiNO6tElYOpKbxKlEJHad66oH26iuXzwkBSnA6kfos\
MqQq_rcQ2bw12ZfhwZfTJHKnfhE6rER5FLKS1DmUwx9Gw";e="AQAB";alg="RS256"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### hwk-ps256.rust

hwk, PS256. Category 2 (verify-only). Signed by aauth-rust. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:FK5EQV8KS7+ZRCELlxeb/B9T0kOFmh+V1RZMbuq8cWicrWrWqYV\
X61zubEJIgvGuM5aglStjFlDNm8Ec4himCPYvBQkN41uuikgKaR/zv86D3f8AQTtb9W\
A4VrxOQPUCY0fvTivqag3WjaNXGb5aHo3/JsanDk9UGeLkZrqH0ZFFcJH9p4h2Te+2y\
uMHfZPBwBXac0TMVxscf8aato/4aKAv/BTecacliIwoW4tXQKgFrFsy0OrzcU6eqnaf\
N6SE4B4y4AL52nVrJtxZTF5ApC5a9uEXTthNNjiD3C0HlcWBvTJgEbEhUvMO892mait\
iI7mbUIgab0TZbYv0zL0x/g==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="RSA";n="tE2hQ7RoXWIGUZIlGG0i748Sp0uG87X\
5ee96CqeMG11F2NCYFlueGn6lGB3xYC5A-QqeoUB3BP_b7lY54oRRfICD_KE5LF-D8b\
XS4JocdQfq9hO4QxBuVZG57oWs8bXICrws-Lj_Lmu-ZeZW5K4ooynqdzxfbx8_2-MP1\
SlmD3N_mOPzHiaVDSxelry0xH61YLh_0nUHrKw37wiIqwQZgsKDnTBMN1YMmNsdIt5A\
UdKlyWJzQBN9S0TCAKE47vJxZoqVTDBxc-w2jG1zif-2h_mwbzLnWQj0FebK_sI5jag\
VDEGn5_Zzzw3rXFhjYDhraWkqMGbmZdq0sd8Iw9jF5Q";e="AQAB";alg="PS256"

```

Signature base (557 bytes, SHA-256 37d9096d9ede04e85aa58173951754a0e85935b6d9fad524c5d702a16b9db2a8):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="RSA";n="tE2hQ7RoXWIGUZIlGG0i748Sp0uG8\
7X5ee96CqeMG11F2NCYFlueGn6lGB3xYC5A-QqeoUB3BP_b7lY54oRRfICD_KE5LF-D\
8bXS4JocdQfq9hO4QxBuVZG57oWs8bXICrws-Lj_Lmu-ZeZW5K4ooynqdzxfbx8_2-M\
P1SlmD3N_mOPzHiaVDSxelry0xH61YLh_0nUHrKw37wiIqwQZgsKDnTBMN1YMmNsdIt\
5AUdKlyWJzQBN9S0TCAKE47vJxZoqVTDBxc-w2jG1zif-2h_mwbzLnWQj0FebK_sI5j\
agVDEGn5_Zzzw3rXFhjYDhraWkqMGbmZdq0sd8Iw9jF5Q";e="AQAB";alg="PS256"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### hwk-ps256.go

hwk, PS256. Category 2 (verify-only). Signed by aauth-go. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:YvaXFVfyQgQHgnuu6T97FXcGeeNJsaYHOkPWVX/vhIFZBDz+v9B\
wJqPVuSKCqTtOSBEohcPu2dmog2RyuxD5yHds2PJDywS4kjcyHxOhvuw39WPmORQioT\
4ksG3fLQVnFTZI2qStu/2ilGXkENJJ+FhOuwKwK01HM1C4GZdUDVG3l7AKXGUQONn9C\
es6JU2I2dxLnV6H2P9KpbA2uK3saGbgRvM8YhPGimNcnJuvodRXegyGjkIPsVG1MLz4\
RhxP3Id3VVM6V0foetNr+RAZH6N78tjjrhc87qxAN50AqEg3P35uFcuHUFeG6qGGfGD\
TJ5t1TBtdWiAhZGtPQjOSZw==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="RSA";n="tE2hQ7RoXWIGUZIlGG0i748Sp0uG87X\
5ee96CqeMG11F2NCYFlueGn6lGB3xYC5A-QqeoUB3BP_b7lY54oRRfICD_KE5LF-D8b\
XS4JocdQfq9hO4QxBuVZG57oWs8bXICrws-Lj_Lmu-ZeZW5K4ooynqdzxfbx8_2-MP1\
SlmD3N_mOPzHiaVDSxelry0xH61YLh_0nUHrKw37wiIqwQZgsKDnTBMN1YMmNsdIt5A\
UdKlyWJzQBN9S0TCAKE47vJxZoqVTDBxc-w2jG1zif-2h_mwbzLnWQj0FebK_sI5jag\
VDEGn5_Zzzw3rXFhjYDhraWkqMGbmZdq0sd8Iw9jF5Q";e="AQAB";alg="PS256"

```

Signature base (557 bytes, SHA-256 37d9096d9ede04e85aa58173951754a0e85935b6d9fad524c5d702a16b9db2a8):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="RSA";n="tE2hQ7RoXWIGUZIlGG0i748Sp0uG8\
7X5ee96CqeMG11F2NCYFlueGn6lGB3xYC5A-QqeoUB3BP_b7lY54oRRfICD_KE5LF-D\
8bXS4JocdQfq9hO4QxBuVZG57oWs8bXICrws-Lj_Lmu-ZeZW5K4ooynqdzxfbx8_2-M\
P1SlmD3N_mOPzHiaVDSxelry0xH61YLh_0nUHrKw37wiIqwQZgsKDnTBMN1YMmNsdIt\
5AUdKlyWJzQBN9S0TCAKE47vJxZoqVTDBxc-w2jG1zif-2h_mwbzLnWQj0FebK_sI5j\
agVDEGn5_Zzzw3rXFhjYDhraWkqMGbmZdq0sd8Iw9jF5Q";e="AQAB";alg="PS256"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### jwt-ed25519

jwt (AAuth agent token), Ed25519 confirmation key. Category 3 (reproduce-the-bytes). Signed by aauth-rust; aauth-go produced the same bytes. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:v2a9vXMAhCPV9cFUV1lPGa+FbNFt9R+oIzcR+IcUKiyc45b+BZV\
42De8ot5XbMgTdtNe+FyZVBCsw/m32O7xDw==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZWQ\
yNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI6I\
kVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW5y\
SUVjbHUyYnJ6ZXYxVmUwMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImR3ayI6ImFhdXR\
oLWFnZW50Lmpzb24iLCJleHAiOjE4MDAwMDMwMDAsImlhdCI6MTc5OTk5OTcwMCwiaX\
NzIjoiaHR0cHM6Ly9hZ2VudC1wcm92aWRlci5leGFtcGxlIiwianRpIjoiand0LWVkM\
jU1MTkiLCJzdWIiOiJhYXV0aDphc3Npc3RhbnRAYWdlbnQtcHJvdmlkZXIuZXhhbXBs\
ZSJ9.DH2bgWEz83EWrzzJdkpeQH9U2js4DzoiamulVrJ-DRd7eZ_GPdpnJUXSk4IQuB\
aWTesHTWfLOpqLnRMXSqoeDw"

```

Signature base (718 bytes, SHA-256 d314d4a84ba892631ac53383657af425a4427ff5833b8ec6951a389c3d857ffc):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZ\
WQyNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI\
6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW\
5ySUVjbHUyYnJ6ZXYxVmUwMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImR3ayI6ImFhd\
XRoLWFnZW50Lmpzb24iLCJleHAiOjE4MDAwMDMwMDAsImlhdCI6MTc5OTk5OTcwMCwi\
aXNzIjoiaHR0cHM6Ly9hZ2VudC1wcm92aWRlci5leGFtcGxlIiwianRpIjoiand0LWV\
kMjU1MTkiLCJzdWIiOiJhYXV0aDphc3Npc3RhbnRAYWdlbnQtcHJvdmlkZXIuZXhhbX\
BsZSJ9.DH2bgWEz83EWrzzJdkpeQH9U2js4DzoiamulVrJ-DRd7eZ_GPdpnJUXSk4IQ\
uBaWTesHTWfLOpqLnRMXSqoeDw"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by ap-ed25519):

```
{
  "alg": "Ed25519",
  "kid": "ap-ed25519",
  "typ": "aa-agent+jwt"
}
{
  "cnf": {
    "jwk": {
      "alg": "Ed25519",
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "ge9CgQnrIEclu2brzev1Ve02hk2_S65Fk_2JSD-dIsA"
    }
  },
  "dwk": "aauth-agent.json",
  "exp": 1800003000,
  "iat": 1799999700,
  "iss": "https://agent-provider.example",
  "jti": "jwt-ed25519",
  "sub": "aauth:assistant@agent-provider.example"
}
```

### jwt-ed25519-post

jwt, Ed25519, POST with query, Content-Type and Content-Digest. Category 3 (reproduce-the-bytes). Signed by aauth-rust; aauth-go produced the same bytes. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

POST /api/items?page=2&sort=name HTTP/1.1
Host: resource.example
Content-Digest: sha-256=:yWRQMvfPuwvj3bhaB0ZKxQISjqgfP1D8MGSsslsPmw\
g=:
Content-Type: application/json
Signature: sig=:qJQJL+PGhsXtcqSQbjNKhC/4Z1OHuEeNR3iUTRWumUWcDR83vgH\
Y4EYH7Urw9qT3l1S+ksOrH/e3mhvJ8AiqAA==:
Signature-Input: sig=("@method" "@authority" "@path" "@query" "cont\
ent-digest" "content-type" "signature-key");created=1800000000
Signature-Key: sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZWQ\
yNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI6I\
kVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW5y\
SUVjbHUyYnJ6ZXYxVmUwMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImR3ayI6ImFhdXR\
oLWFnZW50Lmpzb24iLCJleHAiOjE4MDAwMDMwMDAsImlhdCI6MTc5OTk5OTcwMCwiaX\
NzIjoiaHR0cHM6Ly9hZ2VudC1wcm92aWRlci5leGFtcGxlIiwianRpIjoiand0LWVkM\
jU1MTktcG9zdCIsInN1YiI6ImFhdXRoOmFzc2lzdGFudEBhZ2VudC1wcm92aWRlci5l\
eGFtcGxlIn0.wckLJXLeTsq58RDXhE5-JrYMosbwOwzlli9eMfBkdMiS6Ph5g32Bt1X\
EmBrNKz9YCCIaqscVmrk3CXKWPPPLCw"

{"name":"widget","quantity":3}

```

Signature base (901 bytes, SHA-256 0d59e015805a1124c63ddc590e72dc5c8cdec78512ce6ea90ced33af06b61046):

```
NOTE: '\' line wrapping per RFC 8792

"@method": POST
"@authority": resource.example
"@path": /api/items
"@query": ?page=2&sort=name
"content-digest": sha-256=:yWRQMvfPuwvj3bhaB0ZKxQISjqgfP1D8MGSsslsP\
mwg=:
"content-type": application/json
"signature-key": sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZ\
WQyNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI\
6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW\
5ySUVjbHUyYnJ6ZXYxVmUwMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImR3ayI6ImFhd\
XRoLWFnZW50Lmpzb24iLCJleHAiOjE4MDAwMDMwMDAsImlhdCI6MTc5OTk5OTcwMCwi\
aXNzIjoiaHR0cHM6Ly9hZ2VudC1wcm92aWRlci5leGFtcGxlIiwianRpIjoiand0LWV\
kMjU1MTktcG9zdCIsInN1YiI6ImFhdXRoOmFzc2lzdGFudEBhZ2VudC1wcm92aWRlci\
5leGFtcGxlIn0.wckLJXLeTsq58RDXhE5-JrYMosbwOwzlli9eMfBkdMiS6Ph5g32Bt\
1XEmBrNKz9YCCIaqscVmrk3CXKWPPPLCw"
"@signature-params": ("@method" "@authority" "@path" "@query" "cont\
ent-digest" "content-type" "signature-key");created=1800000000
```

Assertion header and payload (signed by ap-ed25519):

```
{
  "alg": "Ed25519",
  "kid": "ap-ed25519",
  "typ": "aa-agent+jwt"
}
{
  "cnf": {
    "jwk": {
      "alg": "Ed25519",
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "ge9CgQnrIEclu2brzev1Ve02hk2_S65Fk_2JSD-dIsA"
    }
  },
  "dwk": "aauth-agent.json",
  "exp": 1800003000,
  "iat": 1799999700,
  "iss": "https://agent-provider.example",
  "jti": "jwt-ed25519-post",
  "sub": "aauth:assistant@agent-provider.example"
}
```

### jwt-ed25519-cache

jwt with the bare cache parameter and a jti. Category 3 (reproduce-the-bytes). Signed by aauth-rust; aauth-go produced the same bytes. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:BeUTxCtxb6HHi+nclQ8fY5KGpwwOpC7ZLoBSMe55jKzS7pOVw/h\
gAE/c8PeWTn3cOUyEpc1O2deeBdEtGTI2CA==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZWQ\
yNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI6I\
kVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW5y\
SUVjbHUyYnJ6ZXYxVmUwMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImR3ayI6ImFhdXR\
oLWFnZW50Lmpzb24iLCJleHAiOjE4MDAwMDMwMDAsImlhdCI6MTc5OTk5OTcwMCwiaX\
NzIjoiaHR0cHM6Ly9hZ2VudC1wcm92aWRlci5leGFtcGxlIiwianRpIjoiand0LWVkM\
jU1MTktY2FjaGUiLCJzdWIiOiJhYXV0aDphc3Npc3RhbnRAYWdlbnQtcHJvdmlkZXIu\
ZXhhbXBsZSJ9.uHZX_CZS7MZJVFcN3jjj6gxLSRagH59GAJmmAViYeuZs2_ECKL6Ch2\
QdQcw-BXAtCoyBKW-bxENiMbxJTrJ0BQ";cache

```

Signature base (732 bytes, SHA-256 c3f7dba88d64088949c9d1151d5784d96b14b84d1a0df9bbac878234f36f2a12):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZ\
WQyNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI\
6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW\
5ySUVjbHUyYnJ6ZXYxVmUwMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImR3ayI6ImFhd\
XRoLWFnZW50Lmpzb24iLCJleHAiOjE4MDAwMDMwMDAsImlhdCI6MTc5OTk5OTcwMCwi\
aXNzIjoiaHR0cHM6Ly9hZ2VudC1wcm92aWRlci5leGFtcGxlIiwianRpIjoiand0LWV\
kMjU1MTktY2FjaGUiLCJzdWIiOiJhYXV0aDphc3Npc3RhbnRAYWdlbnQtcHJvdmlkZX\
IuZXhhbXBsZSJ9.uHZX_CZS7MZJVFcN3jjj6gxLSRagH59GAJmmAViYeuZs2_ECKL6C\
h2QdQcw-BXAtCoyBKW-bxENiMbxJTrJ0BQ";cache
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by ap-ed25519):

```
{
  "alg": "Ed25519",
  "kid": "ap-ed25519",
  "typ": "aa-agent+jwt"
}
{
  "cnf": {
    "jwk": {
      "alg": "Ed25519",
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "ge9CgQnrIEclu2brzev1Ve02hk2_S65Fk_2JSD-dIsA"
    }
  },
  "dwk": "aauth-agent.json",
  "exp": 1800003000,
  "iat": 1799999700,
  "iss": "https://agent-provider.example",
  "jti": "jwt-ed25519-cache",
  "sub": "aauth:assistant@agent-provider.example"
}
```

### jwt-es256.rust

jwt, ES256 confirmation key. Category 2 (verify-only). Signed by aauth-rust. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:v9hjj6e8ifA9KFZzGO4SDIXw7aLDARBvUe4RxNiru3vajHdb65o\
+m4aKZQ6QcuTpxfqUeJzbrFUiiEeX+KOTww==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZWQ\
yNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI6I\
kVTMjU2IiwiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJrV24xcTl1b01leHpt\
MTVQS21NSjluNDVPWXpJSk9GaHNHQWZOdnhMYUc4IiwieSI6IlNGdFZ3Q0ZTc3dRYm5\
6cGhaV3VSaXU3OHI4TDIxWV9tRnBZTGFVelR1WHcifX0sImR3ayI6ImFhdXRoLWFnZW\
50Lmpzb24iLCJleHAiOjE4MDAwMDMwMDAsImlhdCI6MTc5OTk5OTcwMCwiaXNzIjoia\
HR0cHM6Ly9hZ2VudC1wcm92aWRlci5leGFtcGxlIiwianRpIjoiand0LWVzMjU2Iiwi\
c3ViIjoiYWF1dGg6YXNzaXN0YW50QGFnZW50LXByb3ZpZGVyLmV4YW1wbGUifQ.KdmD\
plIRdYUDbHSPwIXG47b5weauYdIg4VYe6_anY6nMhrPdrpaGQldMJy3qETzPwHcApN3\
Goeaq0hibOV1TDg"

```

Signature base (776 bytes, SHA-256 9294ff271f186c33f0786bb3662ac1f2007b85164c23a0a2cbc03cb82cb6517c):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZ\
WQyNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI\
6IkVTMjU2IiwiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJrV24xcTl1b01leH\
ptMTVQS21NSjluNDVPWXpJSk9GaHNHQWZOdnhMYUc4IiwieSI6IlNGdFZ3Q0ZTc3dRY\
m56cGhaV3VSaXU3OHI4TDIxWV9tRnBZTGFVelR1WHcifX0sImR3ayI6ImFhdXRoLWFn\
ZW50Lmpzb24iLCJleHAiOjE4MDAwMDMwMDAsImlhdCI6MTc5OTk5OTcwMCwiaXNzIjo\
iaHR0cHM6Ly9hZ2VudC1wcm92aWRlci5leGFtcGxlIiwianRpIjoiand0LWVzMjU2Ii\
wic3ViIjoiYWF1dGg6YXNzaXN0YW50QGFnZW50LXByb3ZpZGVyLmV4YW1wbGUifQ.Kd\
mDplIRdYUDbHSPwIXG47b5weauYdIg4VYe6_anY6nMhrPdrpaGQldMJy3qETzPwHcAp\
N3Goeaq0hibOV1TDg"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by ap-ed25519):

```
{
  "alg": "Ed25519",
  "kid": "ap-ed25519",
  "typ": "aa-agent+jwt"
}
{
  "cnf": {
    "jwk": {
      "alg": "ES256",
      "crv": "P-256",
      "kty": "EC",
      "x": "kWn1q9uoMexzm15PKmMJ9n45OYzIJOFhsGAfNvxLaG8",
      "y": "SFtVwCFSswQbnzphZWuRiu78r8L21Y_mFpYLaUzTuXw"
    }
  },
  "dwk": "aauth-agent.json",
  "exp": 1800003000,
  "iat": 1799999700,
  "iss": "https://agent-provider.example",
  "jti": "jwt-es256",
  "sub": "aauth:assistant@agent-provider.example"
}
```

### jwt-es256.go

jwt, ES256 confirmation key. Category 2 (verify-only). Signed by aauth-go. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:mcbU2w6WfzDVgO6AkDIRRF1WOOnSnQaGz1O07au1Bl0Q6ZuzVol\
/cLRAS+opIqcVC4FHHOxOj0DnjDiillOVDA==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZWQ\
yNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI6I\
kVTMjU2IiwiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJrV24xcTl1b01leHpt\
MTVQS21NSjluNDVPWXpJSk9GaHNHQWZOdnhMYUc4IiwieSI6IlNGdFZ3Q0ZTc3dRYm5\
6cGhaV3VSaXU3OHI4TDIxWV9tRnBZTGFVelR1WHcifX0sImR3ayI6ImFhdXRoLWFnZW\
50Lmpzb24iLCJleHAiOjE4MDAwMDMwMDAsImlhdCI6MTc5OTk5OTcwMCwiaXNzIjoia\
HR0cHM6Ly9hZ2VudC1wcm92aWRlci5leGFtcGxlIiwianRpIjoiand0LWVzMjU2Iiwi\
c3ViIjoiYWF1dGg6YXNzaXN0YW50QGFnZW50LXByb3ZpZGVyLmV4YW1wbGUifQ.KdmD\
plIRdYUDbHSPwIXG47b5weauYdIg4VYe6_anY6nMhrPdrpaGQldMJy3qETzPwHcApN3\
Goeaq0hibOV1TDg"

```

Signature base (776 bytes, SHA-256 9294ff271f186c33f0786bb3662ac1f2007b85164c23a0a2cbc03cb82cb6517c):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZ\
WQyNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI\
6IkVTMjU2IiwiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJrV24xcTl1b01leH\
ptMTVQS21NSjluNDVPWXpJSk9GaHNHQWZOdnhMYUc4IiwieSI6IlNGdFZ3Q0ZTc3dRY\
m56cGhaV3VSaXU3OHI4TDIxWV9tRnBZTGFVelR1WHcifX0sImR3ayI6ImFhdXRoLWFn\
ZW50Lmpzb24iLCJleHAiOjE4MDAwMDMwMDAsImlhdCI6MTc5OTk5OTcwMCwiaXNzIjo\
iaHR0cHM6Ly9hZ2VudC1wcm92aWRlci5leGFtcGxlIiwianRpIjoiand0LWVzMjU2Ii\
wic3ViIjoiYWF1dGg6YXNzaXN0YW50QGFnZW50LXByb3ZpZGVyLmV4YW1wbGUifQ.Kd\
mDplIRdYUDbHSPwIXG47b5weauYdIg4VYe6_anY6nMhrPdrpaGQldMJy3qETzPwHcAp\
N3Goeaq0hibOV1TDg"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by ap-ed25519):

```
{
  "alg": "Ed25519",
  "kid": "ap-ed25519",
  "typ": "aa-agent+jwt"
}
{
  "cnf": {
    "jwk": {
      "alg": "ES256",
      "crv": "P-256",
      "kty": "EC",
      "x": "kWn1q9uoMexzm15PKmMJ9n45OYzIJOFhsGAfNvxLaG8",
      "y": "SFtVwCFSswQbnzphZWuRiu78r8L21Y_mFpYLaUzTuXw"
    }
  },
  "dwk": "aauth-agent.json",
  "exp": 1800003000,
  "iat": 1799999700,
  "iss": "https://agent-provider.example",
  "jti": "jwt-es256",
  "sub": "aauth:assistant@agent-provider.example"
}
```

### jwks-uri-ed25519

jwks_uri, Ed25519. Category 3 (reproduce-the-bytes). Signed by aauth-rust; aauth-go produced the same bytes. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:5lY8VHaMJOxDvcsEPzQ9KbJgvoZXSE6VNlbtPcKKjjWaVZZbgWx\
s3aHI6JqAvjONmmw9s1GJkxTvmuw5aDTZBg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwks_uri;id="https://signer.example";dwk="aauth-\
resource.json";kid="signer-ed25519"

```

Signature base (259 bytes, SHA-256 8f8df2c2fec81135eefdca12e96ba5075b1d82e74615ed553826971538a45ba4):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwks_uri;id="https://signer.example";dwk="aaut\
h-resource.json";kid="signer-ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### jwks-uri-es256.rust

jwks_uri, ES256. Category 2 (verify-only). Signed by aauth-rust. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:QmZvondCTkLUXsZr2v8PGavYgsOYjewhbpHzd7qcPa443WhWhi0\
r0yfAZmeNzRWBDYyqchOSzimtvGeQYj5eiA==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwks_uri;id="https://signer.example";dwk="aauth-\
resource.json";kid="signer-es256"

```

Signature base (257 bytes, SHA-256 313128ed2830ac7a879ca4edb7bf272c6ff0955d549f7703c76b9cb0bca23200):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwks_uri;id="https://signer.example";dwk="aaut\
h-resource.json";kid="signer-es256"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### jwks-uri-es256.go

jwks_uri, ES256. Category 2 (verify-only). Signed by aauth-go. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:SDNUg7wuQ0r7WYe8pbVJ+nXWyl5OgAi8KPjwfL5YjZNbIaiNqdy\
tZdPv6HSacyX/SS0Dtztov6DYTjSKHg2DUg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwks_uri;id="https://signer.example";dwk="aauth-\
resource.json";kid="signer-es256"

```

Signature base (257 bytes, SHA-256 313128ed2830ac7a879ca4edb7bf272c6ff0955d549f7703c76b9cb0bca23200):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwks_uri;id="https://signer.example";dwk="aaut\
h-resource.json";kid="signer-es256"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### jwks-ed25519

jwks, Ed25519. Category 3 (reproduce-the-bytes). Signed by aauth-rust; aauth-go produced the same bytes. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:bo4W5WkJ6Bzmsv8ikrxdz7Q3MMtcOQ6gMFJpciyW7wd95jEhBYR\
jjX9yf6gcE/L8+je+EFMITcMeRNuIuSnLCA==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwks;url="https://keys.example/signer.jwks";kid=\
"signer-ed25519"

```

Signature base (240 bytes, SHA-256 ff7a3da5e7f62daf0a33250888d886aca760d3a8245bed1fbc67db43d012c783):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwks;url="https://keys.example/signer.jwks";ki\
d="signer-ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### jwks-es256.rust

jwks, ES256. Category 2 (verify-only). Signed by aauth-rust. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:UzJsq3hmTi+1FzJRzzOWcsY7yfL/vyC/lNGP8aouS7+qI2sZPBE\
wG7IIM+gzBfra7vt8r12yYsehEhrcNFmzZg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwks;url="https://keys.example/signer.jwks";kid=\
"signer-es256"

```

Signature base (238 bytes, SHA-256 090c8df6f794715d45b11f276dca8c20ed71f358026bcfff04ea741993abcb21):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwks;url="https://keys.example/signer.jwks";ki\
d="signer-es256"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### jwks-es256.go

jwks, ES256. Category 2 (verify-only). Signed by aauth-go. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:edmCC0zfbAngZTkXCXJtTsUmAix1aEF7yx8U3skJybtznUFYSXW\
ZlAqizbMGhVjjKXfctr4eKtPuX4XQUFdrEQ==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwks;url="https://keys.example/signer.jwks";kid=\
"signer-es256"

```

Signature base (238 bytes, SHA-256 090c8df6f794715d45b11f276dca8c20ed71f358026bcfff04ea741993abcb21):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwks;url="https://keys.example/signer.jwks";ki\
d="signer-es256"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### self-jwt-ed25519

self-jwt, Ed25519. Category 3 (reproduce-the-bytes). Signed by aauth-rust; aauth-go produced the same bytes. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:eQ5pl5MjYYVmhOqVftV4XXFQETYWUo25eb5zfZYiAzqdxinPMji\
KoC1Mkree4R0s7SQgZRIM0S1UCfnzbS1GCw==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=self-jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoic2\
lnbmVyLWVkMjU1MTkiLCJ0eXAiOiJ2ZWN0b3Itc2VsZitqd3QifQ.eyJhdWQiOiJodH\
RwczovL3Jlc291cmNlLmV4YW1wbGUiLCJkd2siOiJhYXV0aC1yZXNvdXJjZS5qc29uI\
iwiZXhwIjoxODAwMDAwMzAwLCJpYXQiOjE3OTk5OTk5NzAsImlzcyI6Imh0dHBzOi8v\
c2lnbmVyLmV4YW1wbGUiLCJqdGkiOiJzZWxmLWp3dC1lZDI1NTE5In0.DeUMOq7s3nu\
Uhrp5ckSpsdkMckBbBUUifFAjAmdE4BEc1BktuEiKt7WNmjSgi7XH76E0gaCereOHSJ\
Xn_ocqBw"

```

Signature base (568 bytes, SHA-256 7a057f9161d09732c4a77014c7eafce7b2cfc50c99d3579546cca159d8419d18):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=self-jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoi\
c2lnbmVyLWVkMjU1MTkiLCJ0eXAiOiJ2ZWN0b3Itc2VsZitqd3QifQ.eyJhdWQiOiJo\
dHRwczovL3Jlc291cmNlLmV4YW1wbGUiLCJkd2siOiJhYXV0aC1yZXNvdXJjZS5qc29\
uIiwiZXhwIjoxODAwMDAwMzAwLCJpYXQiOjE3OTk5OTk5NzAsImlzcyI6Imh0dHBzOi\
8vc2lnbmVyLmV4YW1wbGUiLCJqdGkiOiJzZWxmLWp3dC1lZDI1NTE5In0.DeUMOq7s3\
nuUhrp5ckSpsdkMckBbBUUifFAjAmdE4BEc1BktuEiKt7WNmjSgi7XH76E0gaCereOH\
SJXn_ocqBw"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by signer-ed25519):

```
{
  "alg": "Ed25519",
  "kid": "signer-ed25519",
  "typ": "vector-self+jwt"
}
{
  "aud": "https://resource.example",
  "dwk": "aauth-resource.json",
  "exp": 1800000300,
  "iat": 1799999970,
  "iss": "https://signer.example",
  "jti": "self-jwt-ed25519"
}
```

### self-jwt-es256.rust

self-jwt, ES256. Category 2 (verify-only). Signed by aauth-rust. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:dGOb1/nWHLGSF8oqC/sbXLq3h8de8hNYVgqk8z3r4YBVBmBu64P\
D7EEzYdIU8iqDrYdDpur4DHImSHGgXVrggQ==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=self-jwt;jwt="eyJhbGciOiJFUzI1NiIsImtpZCI6InNpZ2\
5lci1lczI1NiIsInR5cCI6InZlY3Rvci1zZWxmK2p3dCJ9.eyJhdWQiOiJodHRwczov\
L3Jlc291cmNlLmV4YW1wbGUiLCJkd2siOiJhYXV0aC1yZXNvdXJjZS5qc29uIiwiZXh\
wIjoxODAwMDAwMzAwLCJpYXQiOjE3OTk5OTk5NzAsImlzcyI6Imh0dHBzOi8vc2lnbm\
VyLmV4YW1wbGUiLCJqdGkiOiJzZWxmLWp3dC1lczI1NiJ9._SeU4IjO8cRYS2vvozFj\
CBc4WdEkBBwstsmlbDr6ZZvUPiaUkNzP2zLAk6YrbF93LABLCbhHEDhqSeswJC6A7w"

```

Signature base (559 bytes, SHA-256 edf15526503555ff507a717592497246cfe27102ff0819dc5370abea3471d7a4):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=self-jwt;jwt="eyJhbGciOiJFUzI1NiIsImtpZCI6InNp\
Z25lci1lczI1NiIsInR5cCI6InZlY3Rvci1zZWxmK2p3dCJ9.eyJhdWQiOiJodHRwcz\
ovL3Jlc291cmNlLmV4YW1wbGUiLCJkd2siOiJhYXV0aC1yZXNvdXJjZS5qc29uIiwiZ\
XhwIjoxODAwMDAwMzAwLCJpYXQiOjE3OTk5OTk5NzAsImlzcyI6Imh0dHBzOi8vc2ln\
bmVyLmV4YW1wbGUiLCJqdGkiOiJzZWxmLWp3dC1lczI1NiJ9._SeU4IjO8cRYS2vvoz\
FjCBc4WdEkBBwstsmlbDr6ZZvUPiaUkNzP2zLAk6YrbF93LABLCbhHEDhqSeswJC6A7\
w"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by signer-es256):

```
{
  "alg": "ES256",
  "kid": "signer-es256",
  "typ": "vector-self+jwt"
}
{
  "aud": "https://resource.example",
  "dwk": "aauth-resource.json",
  "exp": 1800000300,
  "iat": 1799999970,
  "iss": "https://signer.example",
  "jti": "self-jwt-es256"
}
```

### self-jwt-es256.go

self-jwt, ES256. Category 2 (verify-only). Signed by aauth-go. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:95rrA7Hn1HwN5YeGpKFo3DeePxnC2bf8ktXsBm3A5tfHXRNhwi8\
H2uWQUXrg95zNJaVaivxeSjhtIZsLpYw12Q==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=self-jwt;jwt="eyJhbGciOiJFUzI1NiIsImtpZCI6InNpZ2\
5lci1lczI1NiIsInR5cCI6InZlY3Rvci1zZWxmK2p3dCJ9.eyJhdWQiOiJodHRwczov\
L3Jlc291cmNlLmV4YW1wbGUiLCJkd2siOiJhYXV0aC1yZXNvdXJjZS5qc29uIiwiZXh\
wIjoxODAwMDAwMzAwLCJpYXQiOjE3OTk5OTk5NzAsImlzcyI6Imh0dHBzOi8vc2lnbm\
VyLmV4YW1wbGUiLCJqdGkiOiJzZWxmLWp3dC1lczI1NiJ9._SeU4IjO8cRYS2vvozFj\
CBc4WdEkBBwstsmlbDr6ZZvUPiaUkNzP2zLAk6YrbF93LABLCbhHEDhqSeswJC6A7w"

```

Signature base (559 bytes, SHA-256 edf15526503555ff507a717592497246cfe27102ff0819dc5370abea3471d7a4):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=self-jwt;jwt="eyJhbGciOiJFUzI1NiIsImtpZCI6InNp\
Z25lci1lczI1NiIsInR5cCI6InZlY3Rvci1zZWxmK2p3dCJ9.eyJhdWQiOiJodHRwcz\
ovL3Jlc291cmNlLmV4YW1wbGUiLCJkd2siOiJhYXV0aC1yZXNvdXJjZS5qc29uIiwiZ\
XhwIjoxODAwMDAwMzAwLCJpYXQiOjE3OTk5OTk5NzAsImlzcyI6Imh0dHBzOi8vc2ln\
bmVyLmV4YW1wbGUiLCJqdGkiOiJzZWxmLWp3dC1lczI1NiJ9._SeU4IjO8cRYS2vvoz\
FjCBc4WdEkBBwstsmlbDr6ZZvUPiaUkNzP2zLAk6YrbF93LABLCbhHEDhqSeswJC6A7\
w"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by signer-es256):

```
{
  "alg": "ES256",
  "kid": "signer-es256",
  "typ": "vector-self+jwt"
}
{
  "aud": "https://resource.example",
  "dwk": "aauth-resource.json",
  "exp": 1800000300,
  "iat": 1799999970,
  "iss": "https://signer.example",
  "jti": "self-jwt-es256"
}
```

### jkt-jwt-ed25519

jkt-jwt, Ed25519 identity key delegating to an Ed25519 request key. Category 3 (reproduce-the-bytes). Signed by aauth-rust; aauth-go produced the same bytes. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:zn4HvCOKNnn3ObLUGHzw+TBwEdaNXLn9sZ/YQiWX9OnCWJFwYsO\
vUY+lOvTZS4k8Vc+JY0wNnA/n5xk4w2wrBg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jkt-jwt;jwt="eyJhbGciOiJFZDI1NTE5IiwiandrIjp7ImF\
sZyI6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6InhNaE\
NydEhYVUdqYXVVMmNpM2NjdDBIQ29mc1JUV0ptRDNrQ0RDOEhRNUEifSwidHlwIjoia\
mt0LXMyNTYrand0In0.eyJjbmYiOnsiandrIjp7ImFsZyI6IkVkMjU1MTkiLCJjcnYi\
OiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW5ySUVjbHUyYnJ6ZXYxVmU\
wMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImV4cCI6MTgwMDAwMzAwMCwiaWF0IjoxNz\
k5OTk5NzAwLCJpc3MiOiJ1cm46amt0OnNoYS0yNTY6NlpZcnI3aC1BcTdLR00zTHo4W\
VpjN0dlU3NsQXZQV2ZQbnYtM3RJLWpnYyIsImp0aSI6ImprdC1qd3QtZWQyNTUxOSJ9\
.84DvOWJm1wewQ9Uq5DvBTHkemEp97SSmXH14F7SsYLpvqaTVgQPVOA3k3W4Nhp8Jej\
kfCs_t4oWf_0xcYmfoCg"

```

Signature base (781 bytes, SHA-256 ffe7051b71b228573c159d033247e75f0fef9a23b79cbe97ff51c76b1b36ea81):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jkt-jwt;jwt="eyJhbGciOiJFZDI1NTE5IiwiandrIjp7I\
mFsZyI6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6InhN\
aENydEhYVUdqYXVVMmNpM2NjdDBIQ29mc1JUV0ptRDNrQ0RDOEhRNUEifSwidHlwIjo\
iamt0LXMyNTYrand0In0.eyJjbmYiOnsiandrIjp7ImFsZyI6IkVkMjU1MTkiLCJjcn\
YiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW5ySUVjbHUyYnJ6ZXYxV\
mUwMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImV4cCI6MTgwMDAwMzAwMCwiaWF0Ijox\
Nzk5OTk5NzAwLCJpc3MiOiJ1cm46amt0OnNoYS0yNTY6NlpZcnI3aC1BcTdLR00zTHo\
4WVpjN0dlU3NsQXZQV2ZQbnYtM3RJLWpnYyIsImp0aSI6ImprdC1qd3QtZWQyNTUxOS\
J9.84DvOWJm1wewQ9Uq5DvBTHkemEp97SSmXH14F7SsYLpvqaTVgQPVOA3k3W4Nhp8J\
ejkfCs_t4oWf_0xcYmfoCg"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by jkt-identity-ed25519):

```
{
  "alg": "Ed25519",
  "jwk": {
    "alg": "Ed25519",
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "xMhCrtHXUGjauU2ci3cct0HCofsRTWJmD3kCDC8HQ5A"
  },
  "typ": "jkt-s256+jwt"
}
{
  "cnf": {
    "jwk": {
      "alg": "Ed25519",
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "ge9CgQnrIEclu2brzev1Ve02hk2_S65Fk_2JSD-dIsA"
    }
  },
  "exp": 1800003000,
  "iat": 1799999700,
  "iss": "urn:jkt:sha-256:6ZYrr7h-Aq7KGM3Lz8YZc7GeSslAvPWfPnv-3tI-jgc",
  "jti": "jkt-jwt-ed25519"
}
```

### jkt-jwt-es256-identity

jkt-jwt, ES256 identity key delegating to an Ed25519 request key (the draft's example shape). Category 3 (reproduce-the-bytes). Signed by aauth-rust; aauth-go produced the same bytes. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:X5p7jO2/pXP/mI5pwIMG3xmI3doifEWPYOXb6Sy3A/oZ8m6dfZU\
g0zLXFXO/nF+m2wwje5noQ9CxcwJlFOAhCQ==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jkt-jwt;jwt="eyJhbGciOiJFUzI1NiIsImp3ayI6eyJhbGc\
iOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoibGRmek5wVXdrMF\
UtYVRheFBWbUl6R2lWUDVidTFGU0htUzFXdm5WbUJGbyIsInkiOiJxUXdtQkN0QWZBW\
UVSOWpTVDdqcWtjckxSMmozQkViOGNmVUd1ZWRnTFlvIn0sInR5cCI6ImprdC1zMjU2\
K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NT\
E5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW5ySUVjbHUyYnJ6ZXYxVmUwMmhrMl9TN\
jVGa18ySlNELWRJc0EifX0sImV4cCI6MTgwMDAwMzAwMCwiaWF0IjoxNzk5OTk5NzAw\
LCJpc3MiOiJ1cm46amt0OnNoYS0yNTY6LUR3Tlp3b1JGVm9nN0ZwYl9WdFlWSDN6YUN\
oc3B0dWQycUxkN0VGeEJCUSIsImp0aSI6ImprdC1qd3QtZXMyNTYtaWRlbnRpdHkifQ\
.IcBMT-FPd9uRIeB4Mjlgyjewzt6489NPMzzQ9vmCGW9A_gLePnamkHx1IgKdp8gZGc\
4SV8OGDjvU5Vu0o9b_Ug"

```

Signature base (848 bytes, SHA-256 8dea34e4abf03080bc82758956dbdaa641740201b84fda0d072c06511508ab76):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jkt-jwt;jwt="eyJhbGciOiJFUzI1NiIsImp3ayI6eyJhb\
GciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoibGRmek5wVXdr\
MFUtYVRheFBWbUl6R2lWUDVidTFGU0htUzFXdm5WbUJGbyIsInkiOiJxUXdtQkN0QWZ\
BWUVSOWpTVDdqcWtjckxSMmozQkViOGNmVUd1ZWRnTFlvIn0sInR5cCI6ImprdC1zMj\
U2K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI6IkVkMjU1MTkiLCJjcnYiOiJFZDI1\
NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW5ySUVjbHUyYnJ6ZXYxVmUwMmhrMl9\
TNjVGa18ySlNELWRJc0EifX0sImV4cCI6MTgwMDAwMzAwMCwiaWF0IjoxNzk5OTk5Nz\
AwLCJpc3MiOiJ1cm46amt0OnNoYS0yNTY6LUR3Tlp3b1JGVm9nN0ZwYl9WdFlWSDN6Y\
UNoc3B0dWQycUxkN0VGeEJCUSIsImp0aSI6ImprdC1qd3QtZXMyNTYtaWRlbnRpdHki\
fQ.IcBMT-FPd9uRIeB4Mjlgyjewzt6489NPMzzQ9vmCGW9A_gLePnamkHx1IgKdp8gZ\
Gc4SV8OGDjvU5Vu0o9b_Ug"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by jkt-identity-es256):

```
{
  "alg": "ES256",
  "jwk": {
    "alg": "ES256",
    "crv": "P-256",
    "kty": "EC",
    "x": "ldfzNpUwk0U-aTaxPVmIzGiVP5bu1FSHmS1WvnVmBFo",
    "y": "qQwmBCtAfAYER9jST7jqkcrLR2j3BEb8cfUGuedgLYo"
  },
  "typ": "jkt-s256+jwt"
}
{
  "cnf": {
    "jwk": {
      "alg": "Ed25519",
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "ge9CgQnrIEclu2brzev1Ve02hk2_S65Fk_2JSD-dIsA"
    }
  },
  "exp": 1800003000,
  "iat": 1799999700,
  "iss": "urn:jkt:sha-256:-DwNZwoRFVog7Fpb_VtYVH3zaChsptud2qLd7EFxBBQ",
  "jti": "jkt-jwt-es256-identity"
}
```

### jkt-jwt-es256.rust

jkt-jwt, Ed25519 identity key delegating to an ES256 request key. Category 2 (verify-only). Signed by aauth-rust. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:UpUJI0RK5Hov+uQWtvYLS1TvPBQbaIRmXCFzUV7SlWs5G1IGtsz\
krgvVqkpKRB6NW5tXkY2aBHaIgagmIBCQZQ==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jkt-jwt;jwt="eyJhbGciOiJFZDI1NTE5IiwiandrIjp7ImF\
sZyI6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6InhNaE\
NydEhYVUdqYXVVMmNpM2NjdDBIQ29mc1JUV0ptRDNrQ0RDOEhRNUEifSwidHlwIjoia\
mt0LXMyNTYrand0In0.eyJjbmYiOnsiandrIjp7ImFsZyI6IkVTMjU2IiwiY3J2Ijoi\
UC0yNTYiLCJrdHkiOiJFQyIsIngiOiJrV24xcTl1b01leHptMTVQS21NSjluNDVPWXp\
JSk9GaHNHQWZOdnhMYUc4IiwieSI6IlNGdFZ3Q0ZTc3dRYm56cGhaV3VSaXU3OHI4TD\
IxWV9tRnBZTGFVelR1WHcifX0sImV4cCI6MTgwMDAwMzAwMCwiaWF0IjoxNzk5OTk5N\
zAwLCJpc3MiOiJ1cm46amt0OnNoYS0yNTY6NlpZcnI3aC1BcTdLR00zTHo4WVpjN0dl\
U3NsQXZQV2ZQbnYtM3RJLWpnYyIsImp0aSI6ImprdC1qd3QtZXMyNTYifQ.HoNBFtsa\
t59Uq6kq70fbkPHe-X4m-m2YS6aJf_SbO6xq7XS37KbDWPloYZ23sr8qvHUKYJbgYxd\
0kKw0qPdMBg"

```

Signature base (839 bytes, SHA-256 28c896487857f2b0ab2988a5526a4feeeb7f207a455e3f19f9b81318d87afd04):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jkt-jwt;jwt="eyJhbGciOiJFZDI1NTE5IiwiandrIjp7I\
mFsZyI6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6InhN\
aENydEhYVUdqYXVVMmNpM2NjdDBIQ29mc1JUV0ptRDNrQ0RDOEhRNUEifSwidHlwIjo\
iamt0LXMyNTYrand0In0.eyJjbmYiOnsiandrIjp7ImFsZyI6IkVTMjU2IiwiY3J2Ij\
oiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJrV24xcTl1b01leHptMTVQS21NSjluNDVPW\
XpJSk9GaHNHQWZOdnhMYUc4IiwieSI6IlNGdFZ3Q0ZTc3dRYm56cGhaV3VSaXU3OHI4\
TDIxWV9tRnBZTGFVelR1WHcifX0sImV4cCI6MTgwMDAwMzAwMCwiaWF0IjoxNzk5OTk\
5NzAwLCJpc3MiOiJ1cm46amt0OnNoYS0yNTY6NlpZcnI3aC1BcTdLR00zTHo4WVpjN0\
dlU3NsQXZQV2ZQbnYtM3RJLWpnYyIsImp0aSI6ImprdC1qd3QtZXMyNTYifQ.HoNBFt\
sat59Uq6kq70fbkPHe-X4m-m2YS6aJf_SbO6xq7XS37KbDWPloYZ23sr8qvHUKYJbgY\
xd0kKw0qPdMBg"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by jkt-identity-ed25519):

```
{
  "alg": "Ed25519",
  "jwk": {
    "alg": "Ed25519",
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "xMhCrtHXUGjauU2ci3cct0HCofsRTWJmD3kCDC8HQ5A"
  },
  "typ": "jkt-s256+jwt"
}
{
  "cnf": {
    "jwk": {
      "alg": "ES256",
      "crv": "P-256",
      "kty": "EC",
      "x": "kWn1q9uoMexzm15PKmMJ9n45OYzIJOFhsGAfNvxLaG8",
      "y": "SFtVwCFSswQbnzphZWuRiu78r8L21Y_mFpYLaUzTuXw"
    }
  },
  "exp": 1800003000,
  "iat": 1799999700,
  "iss": "urn:jkt:sha-256:6ZYrr7h-Aq7KGM3Lz8YZc7GeSslAvPWfPnv-3tI-jgc",
  "jti": "jkt-jwt-es256"
}
```

### jkt-jwt-es256.go

jkt-jwt, Ed25519 identity key delegating to an ES256 request key. Category 2 (verify-only). Signed by aauth-go. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:STLnBMJb/gNkFeo+YUcVKdD0PWKqxFNGN452rKOV6ajdy2c0s6G\
PWjq64vfN8Ga0T0i69luOh6rBCkQ95LiR9g==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jkt-jwt;jwt="eyJhbGciOiJFZDI1NTE5IiwiandrIjp7ImF\
sZyI6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6InhNaE\
NydEhYVUdqYXVVMmNpM2NjdDBIQ29mc1JUV0ptRDNrQ0RDOEhRNUEifSwidHlwIjoia\
mt0LXMyNTYrand0In0.eyJjbmYiOnsiandrIjp7ImFsZyI6IkVTMjU2IiwiY3J2Ijoi\
UC0yNTYiLCJrdHkiOiJFQyIsIngiOiJrV24xcTl1b01leHptMTVQS21NSjluNDVPWXp\
JSk9GaHNHQWZOdnhMYUc4IiwieSI6IlNGdFZ3Q0ZTc3dRYm56cGhaV3VSaXU3OHI4TD\
IxWV9tRnBZTGFVelR1WHcifX0sImV4cCI6MTgwMDAwMzAwMCwiaWF0IjoxNzk5OTk5N\
zAwLCJpc3MiOiJ1cm46amt0OnNoYS0yNTY6NlpZcnI3aC1BcTdLR00zTHo4WVpjN0dl\
U3NsQXZQV2ZQbnYtM3RJLWpnYyIsImp0aSI6ImprdC1qd3QtZXMyNTYifQ.HoNBFtsa\
t59Uq6kq70fbkPHe-X4m-m2YS6aJf_SbO6xq7XS37KbDWPloYZ23sr8qvHUKYJbgYxd\
0kKw0qPdMBg"

```

Signature base (839 bytes, SHA-256 28c896487857f2b0ab2988a5526a4feeeb7f207a455e3f19f9b81318d87afd04):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jkt-jwt;jwt="eyJhbGciOiJFZDI1NTE5IiwiandrIjp7I\
mFsZyI6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6InhN\
aENydEhYVUdqYXVVMmNpM2NjdDBIQ29mc1JUV0ptRDNrQ0RDOEhRNUEifSwidHlwIjo\
iamt0LXMyNTYrand0In0.eyJjbmYiOnsiandrIjp7ImFsZyI6IkVTMjU2IiwiY3J2Ij\
oiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJrV24xcTl1b01leHptMTVQS21NSjluNDVPW\
XpJSk9GaHNHQWZOdnhMYUc4IiwieSI6IlNGdFZ3Q0ZTc3dRYm56cGhaV3VSaXU3OHI4\
TDIxWV9tRnBZTGFVelR1WHcifX0sImV4cCI6MTgwMDAwMzAwMCwiaWF0IjoxNzk5OTk\
5NzAwLCJpc3MiOiJ1cm46amt0OnNoYS0yNTY6NlpZcnI3aC1BcTdLR00zTHo4WVpjN0\
dlU3NsQXZQV2ZQbnYtM3RJLWpnYyIsImp0aSI6ImprdC1qd3QtZXMyNTYifQ.HoNBFt\
sat59Uq6kq70fbkPHe-X4m-m2YS6aJf_SbO6xq7XS37KbDWPloYZ23sr8qvHUKYJbgY\
xd0kKw0qPdMBg"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by jkt-identity-ed25519):

```
{
  "alg": "Ed25519",
  "jwk": {
    "alg": "Ed25519",
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "xMhCrtHXUGjauU2ci3cct0HCofsRTWJmD3kCDC8HQ5A"
  },
  "typ": "jkt-s256+jwt"
}
{
  "cnf": {
    "jwk": {
      "alg": "ES256",
      "crv": "P-256",
      "kty": "EC",
      "x": "kWn1q9uoMexzm15PKmMJ9n45OYzIJOFhsGAfNvxLaG8",
      "y": "SFtVwCFSswQbnzphZWuRiu78r8L21Y_mFpYLaUzTuXw"
    }
  },
  "exp": 1800003000,
  "iat": 1799999700,
  "iss": "urn:jkt:sha-256:6ZYrr7h-Aq7KGM3Lz8YZc7GeSslAvPWfPnv-3tI-jgc",
  "jti": "jkt-jwt-es256"
}
```

### x509-ed25519

x509, Ed25519 end-entity certificate. Category 3 (reproduce-the-bytes). Signed by aauth-rust; aauth-go produced the same bytes. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:Qc5gjqEGDmnRCdF2C4aua0W493NIrVGFPgGrcK11j+N+GI3+rfM\
4mdvyyTmprO6lv6YJlSxVKx1kiOudM0cKAA==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=x509;x5u="https://certs.example/x509-ed25519.pem\
";x5t=:2WOvHULNKK+ByRzW0sLjBM0JAdYrPj/cjmLD+tlthsE=:

```

Signature base (276 bytes, SHA-256 bb857229428941e9cc0acbb55d367469be116429907bb2083b4b7df29c742c37):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=x509;x5u="https://certs.example/x509-ed25519.p\
em";x5t=:2WOvHULNKK+ByRzW0sLjBM0JAdYrPj/cjmLD+tlthsE=:
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### x509-es256.rust

x509, ES256 end-entity certificate. Category 2 (verify-only). Signed by aauth-rust. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:b/Co8ZabPv0mA2KXkGgQtf3F4C8mdT2AGDd8HCscmTxwWUkCxYC\
03GTjcUNH/TlbbZSsR9qq+c3A1IPJ6kcNaA==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=x509;x5u="https://certs.example/x509-es256.pem";\
x5t=:+lK4xVUMzZg9a/La6cse/5HCoyMmbTEThhavw+w5dyk=:

```

Signature base (274 bytes, SHA-256 5003da3f4a189892b828309e0f7d08987eea8df8d2225f4ddc0a9000f9edbf2a):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=x509;x5u="https://certs.example/x509-es256.pem\
";x5t=:+lK4xVUMzZg9a/La6cse/5HCoyMmbTEThhavw+w5dyk=:
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### x509-es256.go

x509, ES256 end-entity certificate. Category 2 (verify-only). Signed by aauth-go. Expected: verify (a correctly signed request under this scheme verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:WtJCAPxtp1uUMUc0a+oOySsV9VNfG7VL90Ff3s5/IrPoqIPX1Pk\
wH6wpByprbnO6DwHiED78hmwGloLt0V9bRg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=x509;x5u="https://certs.example/x509-es256.pem";\
x5t=:+lK4xVUMzZg9a/La6cse/5HCoyMmbTEThhavw+w5dyk=:

```

Signature base (274 bytes, SHA-256 5003da3f4a189892b828309e0f7d08987eea8df8d2225f4ddc0a9000f9edbf2a):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=x509;x5u="https://certs.example/x509-es256.pem\
";x5t=:+lK4xVUMzZg9a/La6cse/5HCoyMmbTEThhavw+w5dyk=:
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### jwks-uri-mixed-ml-dsa

jwks_uri whose JWKS also holds an ML-DSA-44 key; kid selects the Ed25519 key. Category 1 (key handling). Signed by aauth-rust; aauth-go produced the same bytes. Expected: verify (signature-key line 235: select the member matching kid; MUST NOT fail because an unselected member names a kty or alg the verifier does not implement).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:5lY8VHaMJOxDvcsEPzQ9KbJgvoZXSE6VNlbtPcKKjjWaVZZbgWx\
s3aHI6JqAvjONmmw9s1GJkxTvmuw5aDTZBg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwks_uri;id="https://signer.example";dwk="aauth-\
resource.json";kid="signer-ed25519"

```

Signature base (259 bytes, SHA-256 8f8df2c2fec81135eefdca12e96ba5075b1d82e74615ed553826971538a45ba4):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwks_uri;id="https://signer.example";dwk="aaut\
h-resource.json";kid="signer-ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Document at https://signer.example/.well-known/jwks.json, replacing the default:

```
NOTE: '\' line wrapping per RFC 8792

{"keys":[{"alg":"ML-DSA-44","kid":"signer-ml-dsa-44","kty":"AKP","p\
ub":"vCWs7y8_K8ndKqvKsVninhAQnDuW8EK2hyhvbXRxohfBAtkRpeDnm26tuJ6yUm\
NRB_A7jgh46286BdSD17QWQzCd3Ntt6uVVQxeL4F2y89pkMMljKcn3_S9aWxS_9hQHo\
3amelEVlYoCJycvpNlpCaGo_a275c9nWjtvjotRTnq8ur8ZHppmsQDQnUcLoVBDwnn2\
7sUNQZ6ChGqSZBuCozEH1LRhdxDXfmYg7mvFi8FWE68ci9P5BvwDIBukfSrelvWYy9j\
Si-VPkrXohFD1Ljk_U9FAkW7u6bVmToWWyXHRv-Z4ZPKSpe_1pIZNffIoXoQ0VgqrFb\
5g1AFcCL_jefp55D26cp-HGF4pE0zPtpUf-DHba-rUFkg4cfYJRwszgoD5JHMzBTl1x\
qLekeVpIgh135-Im0nvjJo_C6JYD-frkfiH3eh6QkJ9hkbRA7Ooy8G6ncGTB5La2mRF\
NavXtawiCHLKxfk9EShjh7VeV3iriCj0A4RQlAvaQlJIZELHISJJq1BvgCwRJ4kUjah\
3ksdOqXocg3nXIAExjO0S96KsvepJsx1v0Aoc0Dd33jrKmLS7PuoUmjDhQXoKrZidNI\
HLb_yKV84OSjJELtW76IbaJq3gNF9xMmSOhfX50I40N_clO2pG9WttRBHX_pfFwBw53\
ficYR8RVbycVYnaPc3WZhJtwkWOAVjld5jA84TOY49j-Xunoa7ZK5IvvGOOXi5QI_DX\
TiV_7c6PjvJOhMA1eOlXS8BvWcwZigCOCYKTyiqARb920hkgcSzzjDvS2ABeumg0LnN\
C6TRcZEL574zgX0O02Ij8xhvcUC8I__DrR0jOg_MVXxLqfYS6qXYNrJ01IUstFfJm-r\
-CFcYfWkB5I-MHik9DlF0Wu5iJvFZAD1DbjUWAq-AI-a4RZM29BFIud9B7GzKuLGFZR\
Nv4NeshL0nSzsSG1ELOHXkMGsiuicfFnDlDlo2iR59zxVqno8su9E3mqILIXZeTzRw0\
L1_o1FO07QyXVCoEdAcVYjFPBbB6hTxHk9pEZc1J3gY4GsI8XIEhd5O8UIp5jilGY03\
sktuvWVA_LHzOThx2rP2Hu57dNHcywliVbfjNPQY_6u1pOPPToulQdOwnTfzs26wd96\
Z4SH_posjyWxFb6u8EfxkMlIZ3AM1dKNk3xb7CIXWvOjNSZg3fJoC4a_cjOO0a-C3Rq\
bZDcZ-02tDeGSVbZehzzN8lm0-t0zD3-ThMF5odJCkgg1fbBbjRxNsGKUHZHV9NStJi\
KUGNVeX3rF_Vbu2xdjqt16uRx86c8PWafK0AVb1zcyBZSQk8R3gj8jgrkx9G4LZmuxb\
AXqIx5cw2TWtgeSBV_zf8eCeU5JsGTda8Wra-LE31BGoRtdq64W3vInZnuhxKb3mcjl\
eE-1PJDSsFGLCY5ukelsP-U8Kd1OB9rukXGcqFyOnvvD7v7tq-41HmW4nU9-GTD23JX\
9fnjT-bo5m3nCYmaiFMpLXygS9Le_NPeaQ8cvbY7v-Y3bx_CLV7jSA9qzKCOXvQifWG\
vyFLwKJrs2L5zf7LMj79eGE9gIDr9AFfhNYf3WbAT0VlgDX8fFRz6PQTfz9dRH5tCDK\
5SYehbCl4dxwvhJZ922rjo5y99TL4WBV1AaKXw2Fs_voFm1C6yFmnMmn6L5UPGtxp4R\
5Cb8yJrvypgCyH-QvQs8pvsoZKgl9d0QPFJa4OlnBVnus7vIXse1MCls-Gd2md1eEyK\
laJUay4RqDjaw"},{"alg":"Ed25519","crv":"Ed25519","kid":"signer-ed25\
519","kty":"OKP","x":"G655YZ6vyw20ekWtwpnVOuwF36y6CsxxmluRvwZamO4"}\
]}

```

### jwks-uri-ml-dsa-only

jwks_uri whose only key is ML-DSA-44, signed with it. Category 1 (key handling). Signed by harness. Expected: verify-or-reject with `unsupported_algorithm` (signature-key line 233 and protocol Verification step 6: a verifier that does not implement the AKP key type MUST reject it with unsupported_algorithm and MUST NOT fail in an undefined manner; one that implements ML-DSA-44 verifies).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:8ZZ1fvYUOrgKaFz7lzrPs7A1yZj/yiqv9GOVTJlrnDmDmLMb4vD\
yHJt0jJpJwG11oS3k3YjOqIYfZVeUL9T2FXjwohZHrlJkT1cDrZRURMHJ5jJCxAuR3D\
W2UWRFStJiQoJrerdS+4zK6386Jt1xIE6o3OhYRvsN7NkA2B7cyKMEBmB6/iVHFGi4N\
Z0x2yKdlpDhulv/RhFsmTfQ5C6oLww1p9O00pIqiyq6VUx/c5EFoHE7J4G/URJDvuKS\
cw89e43qw1QDqTJ9uj3Al0mWEOa4513so3sPJRvEeDxCwn0Oa9LF7Hz9kUu8is4M19K\
eADBVQPXr9/JmOVUYXNBpnGOcBuFj/rnbing8njFVsQH1Ui6kUKTOYu9d9BSdTbH0an\
ajGSEFKSvnWEpWfoEOQzORCIg7aAsruhT5qCLnAlPlQCtpDopm+5tdfcO7xKWWP+JL8\
xkaF1UKJMgMjdYi/SXVgYwIHHtCrFN3pRsbhdpFCY0A8YhbkT8CK2kIQjEQOAXQte02\
Q6UvwQaSNGCrrIxQjMPTM4ZrAPtB0wix7izjfNS3zm6nf2p9oUEC3sT9MIdI5oTN8Rt\
McTterzyC3LG34o2EIerXQWmVkOxBIrz0HZ4xr7zOa3AqEetfM3fq9rvyRwqIvcblgC\
9yrGPlgpGuuK57fHenGa/Jh5oQjiFGBZuKLSXVzKtczufKMV1Mo48DjvlHgJ1VMSGNN\
OffgEZ+Tx+IddD7kN/OZI66rLz/hCMbf4H6w4QTDc81KV6KTpCNNVOTV1fM4MM8FS+C\
isSelRd4SQz8UVx/rzVxiMlt3jjME89BttqtuZ7TnoY+2CdS02ia/EKJJVKHSI0+GR6\
z9Mb+qUL3clc8f6+jDHzOQvFUMNAeXpUc3mRHhT5KJiSTZ2QQSEck90ARBdACFhvVA8\
xkFtvB3HEn6hCc2vMkDEc1JHbtmO6Dx8BRS3nTgVYlKBe96YWPL02/yCADh0dJLsV62\
RWTinTSxQBrsruewXGNFTs4AkIGcJXOfrUyCwrVeiS51w3VSzG9Es6BQCpx104cJFRq\
do8fT2p5KPBGLP1h6/Lj2mSE4fdN3q8EosvGx5663ACuA7NCp4PGsCE5Yd1gx1bDcLV\
DT+Xq08l//jxRDyrG2bcF/qbKuK6TdMGAlPvCpn6O3PHo/MZcz91nk1tfckMuY4dADd\
C/HsjNQZzLp7/krJgz6Bg6cTJCjGBE6G74kouRU91Q42zpB3wpIN8ZiBXulqSebD51M\
vlbH1mr4IWF8nRuE8kShs9iBAxLIsvpKU025JsIMrrKkj7ja1EhlUUMOnqw+NzxjM4t\
VhzzJIyemz+U0fdDviFBFywbOejg6Z31/2QGFPJaoUgj8PYxQARtHXBtS3amopeyHKP\
Y3Jg9vK9OSVMAWacWGPYnzfulpoL1d6yCX24T031NxiQGgV9NV2F6CFwKW+r0zsy6gf\
MFZYlPcAN5VhJCr42Af98ujIUwIRMgtXprjHLjUN80LD2qhIhUi11RqMIh+/4rWPsiB\
uk3aFH9VPQp1elUcueiJ9Dw17O5GEdpZ66u8wSAOATMhBydKwBDjIOpmmynwHfK+J1O\
w8F7wYhnJWT9q1lp8aZOQ6+zbXH+usiaGXiO83Kxc9dtTa+iCYUekjjCWReK68VLoco\
+iZ+pgv+EzypOmk7pJRxqfQ9GYZ7CBkp/r1pQM3A6vbYd1+Cqb1pvum2MN0UMoPQ3AW\
LIKjNY5rFaAWgap/i6QT6uE2PAwAE9Qj0xNW9oBQREhhUfuxbEFHwAuQCKTUtcKfE+m\
fuvP2+/xMOyloPA79XyJW7RHao2EoNev0EtYVpdTlCGy66uxgeYtLVei5yYdSExrbgD\
FV3pWk7Sxep744bTLJd9YzQHOgkEbTUPQ6nHBxNInruIZXx6PcMBtnwp+VwgMr5+G9C\
xRKYyhkTPkBwnIjK/FNqmjULY0rCpD+7lxavJsozRiRfEdHxotcAdAacqDyxBTOMSZy\
wBhajxaOqt3502O7sd7gvciaRTbh/kx2Aj7BDmUMLZGcN7e67jowc/89nJYTnhiJkS3\
9X7icL3nCqmVVeeSZmtLunbYWfkGvw7TXE08c5biMbUO+R8fCBI1pbenXQo2fQCEoJE\
wk4ckenpNgtFTQTdBOlsSWwcubS3hsF6R+v9QgUF8efe6hcxaKUp52/2qGwWhlJ+dHc\
Xugt8HvPzFW3JWoNLwThFOEQd3LuQSIlJTDJw2UqWb5ZVRIHf8W7dNhhl1BRe+A2E33\
VHALqBBJYyRYss/ZAF0bFHbsvEGzfpUgvb16FFrA/Z6A+G1whUntcVFU3LA66+usYSp\
c5c23QZR8uTuYYSFWNa6X8hjnAT4WHIHqv+weaYR/5w4IT4I/JrafHJvOoUNrTf8g8p\
wmRDIo+TatruaAUt5lE+LF4ANeW55EiNj3kv8UWWAU++NUj3YFm4BJkO0VIsrvMAJUY\
h6smq3LZNM+luNtcBkWoAomBS8M3CDvTEebunZw4kyC/c/LDV4zeTx79L/LzrlxS+CY\
qEZNPjzkK89G5Bou/OiyuOF8f/ttofucAaJsWRorMtIAEKNKDSukjFzCqts7iMRNlDv\
n2TjZz3eOqq2sCHD3pcvwtmtMhXkO/3LYjh9T4eXzT9AyCBPwolzNSvZkLDBHHXcPgK\
nBOR2dpfoej4shuo34gcIwfG42NxbheUyA2bJXASbYIqbQpuPYD+CFXH6pdL6k9PlJJ\
deknbo+fzElK2hKFIR/IBvPHujqhKzedOjl6vTCQx0rswEaYnFnvPt4GDJrekzMekgf\
c5Tb2A9SKhN64ZmunZ1X44kyj9kh0INVy0EDqNJRB6IEwQtkbvGACt2a+/zauZJI+O4\
M9ByrvT38obUzlo5a+a2MBkNoF7ztwoEiE+WygLYMCwJUYhxVRA6beN99oZMWNaLtNQ\
CH/f7B1WD2MdJ3GSq9VeJ+eZo+iz0ghVyBIEokLDXgYSVyC02pmOAO+g/Wz6/Xx5YEz\
+SHXvkdQCHGFH2cIN0SRShErVvwI+hnHtu+z/jISRCmU0+1GwmVRj6bfpHpKLBOpdpa\
n9IL70zpE3s3ky5yd62iLLbsGXloR9h3EEMsM+X7TSh46pmMQBBggPERIZICheeYOhp\
a7I0+TtL0BLXHeMksDQ0+UFBxEiMkZ2kpacoq2vtrrO5vgGFhocJS1CTn+osbe4wMbJ\
2uPy+wAAAAAAAAAAAAAAABMeMEQ=:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwks_uri;id="https://signer.example";dwk="aauth-\
resource.json";kid="signer-ml-dsa-44"

```

Signature base (261 bytes, SHA-256 29b8d831186a53a8707ad1ee99ea9f0c963c6de04c3839b287a6ea5ebd426795):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwks_uri;id="https://signer.example";dwk="aaut\
h-resource.json";kid="signer-ml-dsa-44"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Document at https://signer.example/.well-known/jwks.json, replacing the default:

```
NOTE: '\' line wrapping per RFC 8792

{"keys":[{"alg":"ML-DSA-44","kid":"signer-ml-dsa-44","kty":"AKP","p\
ub":"vCWs7y8_K8ndKqvKsVninhAQnDuW8EK2hyhvbXRxohfBAtkRpeDnm26tuJ6yUm\
NRB_A7jgh46286BdSD17QWQzCd3Ntt6uVVQxeL4F2y89pkMMljKcn3_S9aWxS_9hQHo\
3amelEVlYoCJycvpNlpCaGo_a275c9nWjtvjotRTnq8ur8ZHppmsQDQnUcLoVBDwnn2\
7sUNQZ6ChGqSZBuCozEH1LRhdxDXfmYg7mvFi8FWE68ci9P5BvwDIBukfSrelvWYy9j\
Si-VPkrXohFD1Ljk_U9FAkW7u6bVmToWWyXHRv-Z4ZPKSpe_1pIZNffIoXoQ0VgqrFb\
5g1AFcCL_jefp55D26cp-HGF4pE0zPtpUf-DHba-rUFkg4cfYJRwszgoD5JHMzBTl1x\
qLekeVpIgh135-Im0nvjJo_C6JYD-frkfiH3eh6QkJ9hkbRA7Ooy8G6ncGTB5La2mRF\
NavXtawiCHLKxfk9EShjh7VeV3iriCj0A4RQlAvaQlJIZELHISJJq1BvgCwRJ4kUjah\
3ksdOqXocg3nXIAExjO0S96KsvepJsx1v0Aoc0Dd33jrKmLS7PuoUmjDhQXoKrZidNI\
HLb_yKV84OSjJELtW76IbaJq3gNF9xMmSOhfX50I40N_clO2pG9WttRBHX_pfFwBw53\
ficYR8RVbycVYnaPc3WZhJtwkWOAVjld5jA84TOY49j-Xunoa7ZK5IvvGOOXi5QI_DX\
TiV_7c6PjvJOhMA1eOlXS8BvWcwZigCOCYKTyiqARb920hkgcSzzjDvS2ABeumg0LnN\
C6TRcZEL574zgX0O02Ij8xhvcUC8I__DrR0jOg_MVXxLqfYS6qXYNrJ01IUstFfJm-r\
-CFcYfWkB5I-MHik9DlF0Wu5iJvFZAD1DbjUWAq-AI-a4RZM29BFIud9B7GzKuLGFZR\
Nv4NeshL0nSzsSG1ELOHXkMGsiuicfFnDlDlo2iR59zxVqno8su9E3mqILIXZeTzRw0\
L1_o1FO07QyXVCoEdAcVYjFPBbB6hTxHk9pEZc1J3gY4GsI8XIEhd5O8UIp5jilGY03\
sktuvWVA_LHzOThx2rP2Hu57dNHcywliVbfjNPQY_6u1pOPPToulQdOwnTfzs26wd96\
Z4SH_posjyWxFb6u8EfxkMlIZ3AM1dKNk3xb7CIXWvOjNSZg3fJoC4a_cjOO0a-C3Rq\
bZDcZ-02tDeGSVbZehzzN8lm0-t0zD3-ThMF5odJCkgg1fbBbjRxNsGKUHZHV9NStJi\
KUGNVeX3rF_Vbu2xdjqt16uRx86c8PWafK0AVb1zcyBZSQk8R3gj8jgrkx9G4LZmuxb\
AXqIx5cw2TWtgeSBV_zf8eCeU5JsGTda8Wra-LE31BGoRtdq64W3vInZnuhxKb3mcjl\
eE-1PJDSsFGLCY5ukelsP-U8Kd1OB9rukXGcqFyOnvvD7v7tq-41HmW4nU9-GTD23JX\
9fnjT-bo5m3nCYmaiFMpLXygS9Le_NPeaQ8cvbY7v-Y3bx_CLV7jSA9qzKCOXvQifWG\
vyFLwKJrs2L5zf7LMj79eGE9gIDr9AFfhNYf3WbAT0VlgDX8fFRz6PQTfz9dRH5tCDK\
5SYehbCl4dxwvhJZ922rjo5y99TL4WBV1AaKXw2Fs_voFm1C6yFmnMmn6L5UPGtxp4R\
5Cb8yJrvypgCyH-QvQs8pvsoZKgl9d0QPFJa4OlnBVnus7vIXse1MCls-Gd2md1eEyK\
laJUay4RqDjaw"}]}

```

### reject-uncovered-signature-key

hwk signature that does not cover signature-key. Category 3 (reproduce-the-bytes). Signed by harness. Expected: reject with `invalid_input` (signature-key line 1301: verifiers MUST reject requests where signature-key is not covered; protocol Verification step 2: invalid_input with required_input).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:40U9PJwSgKHu+NuICdxn2mbg3F9pbKnj88pkUlXw0mR6fQfEOAS\
ySu+3wsDHxxlECbHXO0cq6QmGEAsRiL4NDQ==:
Signature-Input: sig=("@method" "@authority" "@path");created=18000\
00000
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2brz\
ev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"

```

Signature base (138 bytes, SHA-256 e0041788604b1443bd9176d80d95abe2299ce2ec4c59258248adeb988690faf6):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"@signature-params": ("@method" "@authority" "@path");created=18000\
00000
```

### reject-hwk-kid

hwk member carrying a kid parameter. Category 3 (reproduce-the-bytes). Signed by harness. Expected: reject (signature-key line 295: the kid parameter MUST NOT be used; no code is fixed, and any failure is a 401 with Signature-Error (protocol Verification)).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:S8FsRzQ0ljUL+8xRpvRvMSq7j66KhEsoV064EGLku17/Z7bsREC\
C0JRlGOXb2a0Vk+Xe+g9Mq/B8x5vJcgYEDQ==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2brz\
ev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519";kid="agent-1"

```

Signature base (279 bytes, SHA-256 6a028ef89daf7fa4933a6b21c92c3af76410ffa378c00c83a0d5fe8a4b7cebe4):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2b\
rzev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519";kid="agent-1"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### reject-hwk-alg-eddsa

hwk member naming the polymorphic EdDSA. Category 3 (reproduce-the-bytes). Signed by harness. Expected: reject with `unsupported_algorithm` (signature-key lines 203 and 211; protocol Verification step 6: unsupported_algorithm for a polymorphic alg).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:DaWbQqqoinENBfbpLxps38mAkKoOCZTMQmcVv+zMMU+UqQXROQT\
AnWwsOdA5OUkOO7T8ETWQykM6L/dS6A/qDA==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2brz\
ev1Ve02hk2_S65Fk_2JSD-dIsA";alg="EdDSA"

```

Signature base (263 bytes, SHA-256 702f025ec1d6d2223b357c32ebc73496acdcb19e0222ca32998e7cbc0c6fdfeb):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2b\
rzev1Ve02hk2_S65Fk_2JSD-dIsA";alg="EdDSA"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### reject-hwk-alg-absent

hwk member without alg. Category 3 (reproduce-the-bytes). Signed by harness. Expected: reject with `unsupported_algorithm` (signature-key lines 203 and 293: alg is REQUIRED and a verifier MUST reject a JWK without it; protocol Verification step 6: unsupported_algorithm if alg is absent).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:XCvOAsQpNvYHtd5K/CT7tG/x6lCaAxShxLywOKGLgUYicm66Dxy\
WFhkkFZ81yze72rVw6mexAd1h7P3ItJpnAA==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2brz\
ev1Ve02hk2_S65Fk_2JSD-dIsA"

```

Signature base (251 bytes, SHA-256 b1590d832c05231bd61e0879d9626cc83bafb991df41e43a10f0b347d7c87d7e):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2b\
rzev1Ve02hk2_S65Fk_2JSD-dIsA"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### reject-hwk-kty-mismatch

hwk OKP key naming ES256. Category 3 (reproduce-the-bytes). Signed by harness. Expected: reject with `invalid_key` (signature-key line 229; protocol Verification step 6: invalid_key when kty disagrees with alg).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:YqVi4RaAaaTck2nfSAMuCBC9+pwL9sPz50H5j+AtwgOtmoTBFLd\
vUINylWlGiFKf9T0+iip2Ext3e0Na5ajsAQ==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2brz\
ev1Ve02hk2_S65Fk_2JSD-dIsA";alg="ES256"

```

Signature base (263 bytes, SHA-256 0bb99d045ace21f339455d8807958f47433202923211240eda64b40733970b53):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2b\
rzev1Ve02hk2_S65Fk_2JSD-dIsA";alg="ES256"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### reject-hwk-crv-mismatch

hwk P-384 key naming ES256. Category 2 (verify-only). Signed by harness. Expected: reject with `invalid_key` (signature-key line 229; protocol Verification step 6: invalid_key when crv disagrees with alg).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:NPJKOZFk/Xp5FlEnlW35X70s2tpp16+E8R06prlToMeQvQaoFhd\
+9WpHQ/pL6070TCJZ1psK1qLqqcpVC1IIb3f6ewU95KLyy0+JuaAL1h/BZkhrchI0FS\
lDOTvpvmYw:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="EC";crv="P-384";x="bfPOJCwtKpeY-u4uoaDB\
Cfsct3meT5xE2xcLJtxuqWnW_Bgn1nXi-DNsuFvbf2Au";y="O6DNv-okgDuYtZ4keV\
M0oizSEw8SKem9lLja7W7fy0ykCtGkdNmXvD0daJdzxelI";alg="ES256"

```

Signature base (350 bytes, SHA-256 8bdc37545d959633d98bd13127f295b76ef80706f1b724e0a878161722b67852):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="EC";crv="P-384";x="bfPOJCwtKpeY-u4uoa\
DBCfsct3meT5xE2xcLJtxuqWnW_Bgn1nXi-DNsuFvbf2Au";y="O6DNv-okgDuYtZ4k\
eVM0oizSEw8SKem9lLja7W7fy0ykCtGkdNmXvD0daJdzxelI";alg="ES256"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### reject-hwk-symmetric

hwk conveying an oct HS256 key, HMAC signature. Category 3 (reproduce-the-bytes). Signed by harness. Expected: reject (signature-key line 217 and protocol Signature Algorithms: symmetric keys MUST NOT be used and a verifier MUST reject them; no code is fixed).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:5Xf2k3WeXBWWmcJdigBoz/jCyI5nDla9XEfbEGEM/CQ=:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="oct";k="ayyuXdDEMSrwW0JVKSuAUz6Aima-20A\
L5vN_DmQqEsU";alg="HS256"

```

Signature base (249 bytes, SHA-256 549a22f6a8275bc2d60fddbcf236c52d28d1a19e023ba06ad563ddf4b2e12fbf):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="oct";k="ayyuXdDEMSrwW0JVKSuAUz6Aima-2\
0AL5vN_DmQqEsU";alg="HS256"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### reject-unknown-scheme

unregistered scheme token. Category 3 (reproduce-the-bytes). Signed by harness. Expected: reject with `unsupported_scheme` (signature-key line 155 and protocol Verification step 4: unsupported_scheme).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:A0d8M5UnrwoqdqXfAFEcqpe15mfYdXgpfT0l/QR5RPYqc7vIE8S\
XbOV/6QivweHWxUEK3HDh5lqtFKe1LNsfDQ==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=x-unregistered;key="ge9CgQnrIEclu2brzev1Ve02hk2_\
S65Fk_2JSD-dIsA"

```

Signature base (240 bytes, SHA-256 7c1db1ff437950ce5023ef14a75cf2a1a1953181b86886ec4dd87383605b1cbc):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=x-unregistered;key="ge9CgQnrIEclu2brzev1Ve02hk\
2_S65Fk_2JSD-dIsA"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### reject-wrong-label

Signature-Key member under sig1 while the signature is labelled sig. Category 3 (reproduce-the-bytes). Signed by aauth-go; aauth-rust produced the same bytes. Expected: reject with `invalid_signature` (signature-key lines 179 and 187: no member for the verified label MUST fail; line 1018 assigns missing Signature-Key material to invalid_signature).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:FaJPwsiTYpA+3JVG+QPMgYHnh0q/n7yZo5V9/36By2S8lV/ufn1\
Aifli5DHO/Its9uLn0vgW9r/UkTMh6Y20Cg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig1=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2br\
zev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"

```

Signature base (266 bytes, SHA-256 a2b4faef6faa40c68dac5847e45fa13c5be66727e183804e885ddbd21ab11947):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig1=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2\
brzev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### reject-tampered-signature

hwk signature with one bit flipped. Category 3 (reproduce-the-bytes). Signed by aauth-go; aauth-rust produced the same bytes. Expected: reject with `invalid_signature` (protocol Verification step 7: invalid_signature if verification fails).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:wGI92boz47sJN4qsSaCcM0+BMgWEO811RefzvZKQsWWj1JyUrAa\
eest2kFd5oYfb9Vi8G3wYD+rV6AliCGTCBQ==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2brz\
ev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"

```

Signature base (265 bytes, SHA-256 e09cd5dec4a12dd98550210595214918f0203dc9156a5cbdce50906ca01f273f):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2b\
rzev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### reject-wrong-key

jwt whose cnf names one key while another key signs. Category 3 (reproduce-the-bytes). Signed by aauth-go; aauth-rust produced the same bytes. Expected: reject with `invalid_signature` (protocol Verification step 7: the signature does not verify under the key the member conveys).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:wFaVtQM+qOKl3DeR2BAsBVYxK44jZDuX0ng5OVYU+dQZqwbAU0N\
K3fwBj8mR/KjV7l9cj8BzIO7nupck2D7nDg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZWQ\
yNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI6I\
kVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW5y\
SUVjbHUyYnJ6ZXYxVmUwMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImR3ayI6ImFhdXR\
oLWFnZW50Lmpzb24iLCJleHAiOjE4MDAwMDMwMDAsImlhdCI6MTc5OTk5OTcwMCwiaX\
NzIjoiaHR0cHM6Ly9hZ2VudC1wcm92aWRlci5leGFtcGxlIiwianRpIjoicmVqZWN0L\
Xdyb25nLWtleSIsInN1YiI6ImFhdXRoOmFzc2lzdGFudEBhZ2VudC1wcm92aWRlci5l\
eGFtcGxlIn0.J2azk_nRaTpbxVrMX8-5mg_aLg_Y7oDcvItu86FuRLn-ig0c81OBDo1\
uKZc59Tnom2h77d9vRRLSXO38c81CBQ"

```

Signature base (725 bytes, SHA-256 4579bb4dfe5367782847135570d1ef633ec5d3dc99ed8d2be22c71d572b1e274):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZ\
WQyNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI\
6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW\
5ySUVjbHUyYnJ6ZXYxVmUwMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImR3ayI6ImFhd\
XRoLWFnZW50Lmpzb24iLCJleHAiOjE4MDAwMDMwMDAsImlhdCI6MTc5OTk5OTcwMCwi\
aXNzIjoiaHR0cHM6Ly9hZ2VudC1wcm92aWRlci5leGFtcGxlIiwianRpIjoicmVqZWN\
0LXdyb25nLWtleSIsInN1YiI6ImFhdXRoOmFzc2lzdGFudEBhZ2VudC1wcm92aWRlci\
5leGFtcGxlIn0.J2azk_nRaTpbxVrMX8-5mg_aLg_Y7oDcvItu86FuRLn-ig0c81OBD\
o1uKZc59Tnom2h77d9vRRLSXO38c81CBQ"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by ap-ed25519):

```
{
  "alg": "Ed25519",
  "kid": "ap-ed25519",
  "typ": "aa-agent+jwt"
}
{
  "cnf": {
    "jwk": {
      "alg": "Ed25519",
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "ge9CgQnrIEclu2brzev1Ve02hk2_S65Fk_2JSD-dIsA"
    }
  },
  "dwk": "aauth-agent.json",
  "exp": 1800003000,
  "iat": 1799999700,
  "iss": "https://agent-provider.example",
  "jti": "reject-wrong-key",
  "sub": "aauth:assistant@agent-provider.example"
}
```

### reject-created-future

created 300 seconds ahead of the verifier clock (window 60). Category 3 (reproduce-the-bytes). Signed by aauth-go; aauth-rust produced the same bytes. Expected: reject with `clock_skew` (signature-key line 1106 and protocol Verification step 3: clock_skew when created is further ahead than the window).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:0YpRYhLRSBF/MqozPjvJXkGvqF8cDSZsdpvntnK2eAi32J2YwuT\
q2j0By8DWCOUdReN39j/uxP+Tq4FI0XSTAw==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000300
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2brz\
ev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"

```

Signature base (265 bytes, SHA-256 18fe024fda49f86501d3afbc789809745a18cac619bda901269e8630e546d671):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2b\
rzev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000300
```

### reject-created-stale

created 300 seconds before the verifier clock (window 60). Category 3 (reproduce-the-bytes). Signed by aauth-go; aauth-rust produced the same bytes. Expected: reject with `invalid_signature` (signature-key line 1114 and protocol Verification step 3: invalid_signature when created is older than the window).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:XQ56lBDIO/6O7TZpv4bcD8VE0rhK67IhYioyW+dG/j5RJRFVYPD\
FUxXwUyoWqn56SF7d7t12duD0DQqEsIEsDg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1799999700
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2brz\
ev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"

```

Signature base (265 bytes, SHA-256 acd054495b6b81406eb0c2427ee24e3f6688db97c23dd48f98fed883e099eb74):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2b\
rzev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1799999700
```

### reject-jwt-expired

jwt whose exp is one second before the verifier clock. Category 3 (reproduce-the-bytes). Signed by aauth-go; aauth-rust produced the same bytes. Expected: reject with `expired_jwt` (signature-key line 1084 and protocol Verification step 5: expired_jwt).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:0y9eOM82VAFNGK6zMxJPFKD1/H6PLakNR4HlUAmXkOYKjK050hE\
Y2j/MskKfYeiX0kN8YPqufkchl/e2UG8nCA==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZWQ\
yNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI6I\
kVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW5y\
SUVjbHUyYnJ6ZXYxVmUwMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImR3ayI6ImFhdXR\
oLWFnZW50Lmpzb24iLCJleHAiOjE3OTk5OTk5OTksImlhdCI6MTc5OTk5NjQwMCwiaX\
NzIjoiaHR0cHM6Ly9hZ2VudC1wcm92aWRlci5leGFtcGxlIiwianRpIjoicmVqZWN0L\
Wp3dC1leHBpcmVkIiwic3ViIjoiYWF1dGg6YXNzaXN0YW50QGFnZW50LXByb3ZpZGVy\
LmV4YW1wbGUifQ.TIqkuYzpPhcvgyAdGuxxMMiZUuTlCD7w1eiTO5cmaNZXk09sUFX4\
wjzNgfxzLD0vSywW13eptq69xx6S6iCmBQ"

```

Signature base (728 bytes, SHA-256 95146f367560a37461f36cec44ef172714f14eda582bbb470da079ef19902a3a):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZ\
WQyNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI\
6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW\
5ySUVjbHUyYnJ6ZXYxVmUwMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImR3ayI6ImFhd\
XRoLWFnZW50Lmpzb24iLCJleHAiOjE3OTk5OTk5OTksImlhdCI6MTc5OTk5NjQwMCwi\
aXNzIjoiaHR0cHM6Ly9hZ2VudC1wcm92aWRlci5leGFtcGxlIiwianRpIjoicmVqZWN\
0LWp3dC1leHBpcmVkIiwic3ViIjoiYWF1dGg6YXNzaXN0YW50QGFnZW50LXByb3ZpZG\
VyLmV4YW1wbGUifQ.TIqkuYzpPhcvgyAdGuxxMMiZUuTlCD7w1eiTO5cmaNZXk09sUF\
X4wjzNgfxzLD0vSywW13eptq69xx6S6iCmBQ"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by ap-ed25519):

```
{
  "alg": "Ed25519",
  "kid": "ap-ed25519",
  "typ": "aa-agent+jwt"
}
{
  "cnf": {
    "jwk": {
      "alg": "Ed25519",
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "ge9CgQnrIEclu2brzev1Ve02hk2_S65Fk_2JSD-dIsA"
    }
  },
  "dwk": "aauth-agent.json",
  "exp": 1799999999,
  "iat": 1799996400,
  "iss": "https://agent-provider.example",
  "jti": "reject-jwt-expired",
  "sub": "aauth:assistant@agent-provider.example"
}
```

### reject-jwt-no-exp

jwt without exp. Category 3 (reproduce-the-bytes). Signed by aauth-go; aauth-rust produced the same bytes. Expected: reject with `invalid_jwt` (signature-key line 552: the JWT MUST contain exp; protocol Verification step 5: invalid_jwt when a JWT scheme fails verification).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:nmh8MAIdM1hnGODJuI4Np4ZWIz0X3JM8bfzOcA+cpnpmaTwpAH1\
OigLI0AnRMhomJDyetSGEXriVylgbf3QOBQ==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZWQ\
yNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI6I\
kVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW5y\
SUVjbHUyYnJ6ZXYxVmUwMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImR3ayI6ImFhdXR\
oLWFnZW50Lmpzb24iLCJpYXQiOjE3OTk5OTk3MDAsImlzcyI6Imh0dHBzOi8vYWdlbn\
QtcHJvdmlkZXIuZXhhbXBsZSIsImp0aSI6InJlamVjdC1qd3Qtbm8tZXhwIiwic3ViI\
joiYWF1dGg6YXNzaXN0YW50QGFnZW50LXByb3ZpZGVyLmV4YW1wbGUifQ.hdsaGSj6U\
r2-NGn4BmfutR61FPfytSK0fPOyJQM_8LMuFFztq1SBoXPfH99dPCcBxi-gZ4YuLtyQ\
oTiZ3CU1CQ"

```

Signature base (704 bytes, SHA-256 2b0970aa1134adb9ab3657868da9862dfe2a5314b7deaf617a1f792430e2a388):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZ\
WQyNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI\
6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW\
5ySUVjbHUyYnJ6ZXYxVmUwMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImR3ayI6ImFhd\
XRoLWFnZW50Lmpzb24iLCJpYXQiOjE3OTk5OTk3MDAsImlzcyI6Imh0dHBzOi8vYWdl\
bnQtcHJvdmlkZXIuZXhhbXBsZSIsImp0aSI6InJlamVjdC1qd3Qtbm8tZXhwIiwic3V\
iIjoiYWF1dGg6YXNzaXN0YW50QGFnZW50LXByb3ZpZGVyLmV4YW1wbGUifQ.hdsaGSj\
6Ur2-NGn4BmfutR61FPfytSK0fPOyJQM_8LMuFFztq1SBoXPfH99dPCcBxi-gZ4YuLt\
yQoTiZ3CU1CQ"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by ap-ed25519):

```
{
  "alg": "Ed25519",
  "kid": "ap-ed25519",
  "typ": "aa-agent+jwt"
}
{
  "cnf": {
    "jwk": {
      "alg": "Ed25519",
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "ge9CgQnrIEclu2brzev1Ve02hk2_S65Fk_2JSD-dIsA"
    }
  },
  "dwk": "aauth-agent.json",
  "iat": 1799999700,
  "iss": "https://agent-provider.example",
  "jti": "reject-jwt-no-exp",
  "sub": "aauth:assistant@agent-provider.example"
}
```

### reject-jwt-cnf-eddsa

jwt whose cnf.jwk names the polymorphic EdDSA. Category 3 (reproduce-the-bytes). Signed by aauth-go; aauth-rust produced the same bytes. Expected: reject with `unsupported_algorithm` (signature-key line 211 and protocol Verification step 6, for the cnf.jwk the jwt scheme conveys).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:kxS7I578/I4tF/rytUNerBpWFSURCPQ14/8s8Wy+txUcQF23B6T\
f8lHqQoq+crfRjhFvbm7dm18kgqShQkDZCw==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZWQ\
yNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI6I\
kVkRFNBIiwiY3J2IjoiRWQyNTUxOSIsImt0eSI6Ik9LUCIsIngiOiJnZTlDZ1FucklF\
Y2x1MmJyemV2MVZlMDJoazJfUzY1RmtfMkpTRC1kSXNBIn19LCJkd2siOiJhYXV0aC1\
hZ2VudC5qc29uIiwiZXhwIjoxODAwMDAzMDAwLCJpYXQiOjE3OTk5OTk3MDAsImlzcy\
I6Imh0dHBzOi8vYWdlbnQtcHJvdmlkZXIuZXhhbXBsZSIsImp0aSI6InJlamVjdC1qd\
3QtY25mLWVkZHNhIiwic3ViIjoiYWF1dGg6YXNzaXN0YW50QGFnZW50LXByb3ZpZGVy\
LmV4YW1wbGUifQ.PHE2v90S-7Gcup_lyyg04xCJo1RfWUVutTgzN9kEmldsfGRU84QQ\
D1mQxwtE1Q2WZBt_Oy8snRkLxdprQIkiAQ"

```

Signature base (728 bytes, SHA-256 4971ec2b02efdfbd5ad65b0b006e8ff60902c362b8820bc76245993ffbb31f39):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiYXAtZ\
WQyNTUxOSIsInR5cCI6ImFhLWFnZW50K2p3dCJ9.eyJjbmYiOnsiandrIjp7ImFsZyI\
6IkVkRFNBIiwiY3J2IjoiRWQyNTUxOSIsImt0eSI6Ik9LUCIsIngiOiJnZTlDZ1Fuck\
lFY2x1MmJyemV2MVZlMDJoazJfUzY1RmtfMkpTRC1kSXNBIn19LCJkd2siOiJhYXV0a\
C1hZ2VudC5qc29uIiwiZXhwIjoxODAwMDAzMDAwLCJpYXQiOjE3OTk5OTk3MDAsImlz\
cyI6Imh0dHBzOi8vYWdlbnQtcHJvdmlkZXIuZXhhbXBsZSIsImp0aSI6InJlamVjdC1\
qd3QtY25mLWVkZHNhIiwic3ViIjoiYWF1dGg6YXNzaXN0YW50QGFnZW50LXByb3ZpZG\
VyLmV4YW1wbGUifQ.PHE2v90S-7Gcup_lyyg04xCJo1RfWUVutTgzN9kEmldsfGRU84\
QQD1mQxwtE1Q2WZBt_Oy8snRkLxdprQIkiAQ"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by ap-ed25519):

```
{
  "alg": "Ed25519",
  "kid": "ap-ed25519",
  "typ": "aa-agent+jwt"
}
{
  "cnf": {
    "jwk": {
      "alg": "EdDSA",
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "ge9CgQnrIEclu2brzev1Ve02hk2_S65Fk_2JSD-dIsA"
    }
  },
  "dwk": "aauth-agent.json",
  "exp": 1800003000,
  "iat": 1799999700,
  "iss": "https://agent-provider.example",
  "jti": "reject-jwt-cnf-eddsa",
  "sub": "aauth:assistant@agent-provider.example"
}
```

### reject-jwks-uri-unknown-kid

jwks_uri naming a kid the JWKS does not hold. Category 3 (reproduce-the-bytes). Signed by aauth-go; aauth-rust produced the same bytes. Expected: reject with `unknown_key` (signature-key line 1054 and protocol Verification step 5: unknown_key).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:SkhZBcrfxmn3W1ue7q8unOx1jfQHw76QfBXpFjlkDPZDt1FFeFE\
mHafbtFDevQr36GX4D7L1eFkyYffG4dLsDw==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwks_uri;id="https://signer.example";dwk="aauth-\
resource.json";kid="signer-absent"

```

Signature base (258 bytes, SHA-256 448504dcbef14a95d397cc9bb24aa83e1621419ea7ebe18d2536ab0c99da0b52):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwks_uri;id="https://signer.example";dwk="aaut\
h-resource.json";kid="signer-absent"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### reject-jwks-unknown-kid

jwks naming a kid the JWKS does not hold. Category 3 (reproduce-the-bytes). Signed by aauth-go; aauth-rust produced the same bytes. Expected: reject with `unknown_key` (signature-key line 1054 (applicable to jwks): unknown_key).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:tAkXQF0rx/URKmOtOa8XM+pDD26aWCsnldzgp0Mtzpo1Jw05oeu\
bZGz0V6KhX5daR7E1ZRafw+ECQiefaNG1Cg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwks;url="https://keys.example/signer.jwks";kid=\
"signer-absent"

```

Signature base (239 bytes, SHA-256 2f0024f58d99876b4d3f4699a186d08ed29d11c966baec4228787309476f440f):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwks;url="https://keys.example/signer.jwks";ki\
d="signer-absent"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### reject-jwks-uri-issuer-mismatch

jwks_uri whose metadata names another issuer. Category 3 (reproduce-the-bytes). Signed by aauth-go; aauth-rust produced the same bytes. Expected: reject with `issuer_mismatch` (signature-key line 464: issuer MUST equal id, else issuer_mismatch).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:5lY8VHaMJOxDvcsEPzQ9KbJgvoZXSE6VNlbtPcKKjjWaVZZbgWx\
s3aHI6JqAvjONmmw9s1GJkxTvmuw5aDTZBg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwks_uri;id="https://signer.example";dwk="aauth-\
resource.json";kid="signer-ed25519"

```

Signature base (259 bytes, SHA-256 8f8df2c2fec81135eefdca12e96ba5075b1d82e74615ed553826971538a45ba4):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwks_uri;id="https://signer.example";dwk="aaut\
h-resource.json";kid="signer-ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Document at https://signer.example/.well-known/aauth-resource.json, replacing the default:

```
NOTE: '\' line wrapping per RFC 8792

{"issuer":"https://other-signer.example","jwks_uri":"https://signer\
.example/.well-known/jwks.json"}

```

### reject-jwks-uri-issuer-missing

jwks_uri whose metadata has no issuer. Category 3 (reproduce-the-bytes). Signed by aauth-go; aauth-rust produced the same bytes. Expected: reject with `issuer_missing` (signature-key line 462: the document MUST contain issuer, else issuer_missing).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:5lY8VHaMJOxDvcsEPzQ9KbJgvoZXSE6VNlbtPcKKjjWaVZZbgWx\
s3aHI6JqAvjONmmw9s1GJkxTvmuw5aDTZBg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwks_uri;id="https://signer.example";dwk="aauth-\
resource.json";kid="signer-ed25519"

```

Signature base (259 bytes, SHA-256 8f8df2c2fec81135eefdca12e96ba5075b1d82e74615ed553826971538a45ba4):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwks_uri;id="https://signer.example";dwk="aaut\
h-resource.json";kid="signer-ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Document at https://signer.example/.well-known/aauth-resource.json, replacing the default:

```
{"jwks_uri":"https://signer.example/.well-known/jwks.json"}

```

### reject-jwks-uri-alg-absent

jwks_uri whose selected JWKS key has no alg. Category 3 (reproduce-the-bytes). Signed by aauth-go; aauth-rust produced the same bytes. Expected: reject with `unsupported_algorithm` (signature-key line 227: the resolved JWKS entry MUST carry alg; protocol Verification step 6: unsupported_algorithm if alg is absent).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:5lY8VHaMJOxDvcsEPzQ9KbJgvoZXSE6VNlbtPcKKjjWaVZZbgWx\
s3aHI6JqAvjONmmw9s1GJkxTvmuw5aDTZBg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jwks_uri;id="https://signer.example";dwk="aauth-\
resource.json";kid="signer-ed25519"

```

Signature base (259 bytes, SHA-256 8f8df2c2fec81135eefdca12e96ba5075b1d82e74615ed553826971538a45ba4):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jwks_uri;id="https://signer.example";dwk="aaut\
h-resource.json";kid="signer-ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Document at https://signer.example/.well-known/jwks.json, replacing the default:

```
NOTE: '\' line wrapping per RFC 8792

{"keys":[{"crv":"Ed25519","kid":"signer-ed25519","kty":"OKP","x":"G\
655YZ6vyw20ekWtwpnVOuwF36y6CsxxmluRvwZamO4"}]}

```

### reject-self-jwt-cnf

self-jwt carrying a cnf claim. Category 3 (reproduce-the-bytes). Signed by aauth-go. Expected: reject with `invalid_jwt` (signature-key lines 629 and 651: a self-jwt MUST NOT contain cnf; invalid_jwt (line 1078) for a JWT that fails verification).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:WrqolhtWXBUBtCIZkIHvOEbDq0Z2FG2WM1UfeBx3LB57wE4zIMw\
TxNAzTI/GGocHuLsKK70reIbZp9JouUpfBg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=self-jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoic2\
lnbmVyLWVkMjU1MTkiLCJ0eXAiOiJ2ZWN0b3Itc2VsZitqd3QifQ.eyJhdWQiOiJodH\
RwczovL3Jlc291cmNlLmV4YW1wbGUiLCJjbmYiOnsiandrIjp7ImFsZyI6IkVkMjU1M\
TkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ikc2NTVZWjZ2eXcyMGVr\
V3R3cG5WT3V3RjM2eTZDc3h4bWx1UnZ3WmFtTzQifX0sImR3ayI6ImFhdXRoLXJlc29\
1cmNlLmpzb24iLCJleHAiOjE4MDAwMDAzMDAsImlhdCI6MTc5OTk5OTk3MCwiaXNzIj\
oiaHR0cHM6Ly9zaWduZXIuZXhhbXBsZSIsImp0aSI6InJlamVjdC1zZWxmLWp3dC1jb\
mYifQ.-LAkxLo2ZAlCf93AcRatxna1ZqUPnoGzAC4LNlEL9YitA8rTJlp5tHTAmwW_k\
aFsPx0v_0zuum_l_5iq-pOiAQ"

```

Signature base (719 bytes, SHA-256 052ef17af178b84d568dd05030bdb414d7fca3c0f959b4fd6688a8ef24fbcb86):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=self-jwt;jwt="eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoi\
c2lnbmVyLWVkMjU1MTkiLCJ0eXAiOiJ2ZWN0b3Itc2VsZitqd3QifQ.eyJhdWQiOiJo\
dHRwczovL3Jlc291cmNlLmV4YW1wbGUiLCJjbmYiOnsiandrIjp7ImFsZyI6IkVkMjU\
1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ikc2NTVZWjZ2eXcyMG\
VrV3R3cG5WT3V3RjM2eTZDc3h4bWx1UnZ3WmFtTzQifX0sImR3ayI6ImFhdXRoLXJlc\
291cmNlLmpzb24iLCJleHAiOjE4MDAwMDAzMDAsImlhdCI6MTc5OTk5OTk3MCwiaXNz\
IjoiaHR0cHM6Ly9zaWduZXIuZXhhbXBsZSIsImp0aSI6InJlamVjdC1zZWxmLWp3dC1\
jbmYifQ.-LAkxLo2ZAlCf93AcRatxna1ZqUPnoGzAC4LNlEL9YitA8rTJlp5tHTAmwW\
_kaFsPx0v_0zuum_l_5iq-pOiAQ"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by signer-ed25519):

```
{
  "alg": "Ed25519",
  "kid": "signer-ed25519",
  "typ": "vector-self+jwt"
}
{
  "aud": "https://resource.example",
  "cnf": {
    "jwk": {
      "alg": "Ed25519",
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "G655YZ6vyw20ekWtwpnVOuwF36y6CsxxmluRvwZamO4"
    }
  },
  "dwk": "aauth-resource.json",
  "exp": 1800000300,
  "iat": 1799999970,
  "iss": "https://signer.example",
  "jti": "reject-self-jwt-cnf"
}
```

### reject-jkt-jwt-iss-mismatch

jkt-jwt whose iss is not the thumbprint of its header jwk. Category 3 (reproduce-the-bytes). Signed by aauth-go. Expected: reject with `invalid_jwt` (signature-key lines 339 and 424: iss MUST equal the thumbprint URI of the header jwk; invalid_jwt (line 1078)).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:RkQvIWlH0U9UpNZYSw0F4aANJIhlZO0E0rMvOqyPuiubFhl/pYG\
1muntUY/hm5Kg+Ly9EaPUZnB+1d+zfJM9BA==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=jkt-jwt;jwt="eyJhbGciOiJFZDI1NTE5IiwiandrIjp7ImF\
sZyI6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6InhNaE\
NydEhYVUdqYXVVMmNpM2NjdDBIQ29mc1JUV0ptRDNrQ0RDOEhRNUEifSwidHlwIjoia\
mt0LXMyNTYrand0In0.eyJjbmYiOnsiandrIjp7ImFsZyI6IkVkMjU1MTkiLCJjcnYi\
OiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW5ySUVjbHUyYnJ6ZXYxVmU\
wMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImV4cCI6MTgwMDAwMzAwMCwiaWF0IjoxNz\
k5OTk5NzAwLCJpc3MiOiJ1cm46amt0OnNoYS0yNTY6Y1hKSzBYYmNPTXJoZGJKNTJQc\
2FvQ1VKMEhwSWtfQy1IYVlhNkUwNmtXcyIsImp0aSI6InJlamVjdC1qa3Qtand0LWlz\
cy1taXNtYXRjaCJ9.SBdGewXJ5YbbbBIABBzCPUFjAnm3a9IR3pOiUXN05e_7bbThtB\
iVGfsnLC8GKfUEPUbesrD6a0-aSF22HOwxBA"

```

Signature base (797 bytes, SHA-256 3658e4565af90b5cc167bd1bedf7b0f95e60b07bcf2cdfa3a06a4288475225ed):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=jkt-jwt;jwt="eyJhbGciOiJFZDI1NTE5IiwiandrIjp7I\
mFsZyI6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6InhN\
aENydEhYVUdqYXVVMmNpM2NjdDBIQ29mc1JUV0ptRDNrQ0RDOEhRNUEifSwidHlwIjo\
iamt0LXMyNTYrand0In0.eyJjbmYiOnsiandrIjp7ImFsZyI6IkVkMjU1MTkiLCJjcn\
YiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdlOUNnUW5ySUVjbHUyYnJ6ZXYxV\
mUwMmhrMl9TNjVGa18ySlNELWRJc0EifX0sImV4cCI6MTgwMDAwMzAwMCwiaWF0Ijox\
Nzk5OTk5NzAwLCJpc3MiOiJ1cm46amt0OnNoYS0yNTY6Y1hKSzBYYmNPTXJoZGJKNTJ\
Qc2FvQ1VKMEhwSWtfQy1IYVlhNkUwNmtXcyIsImp0aSI6InJlamVjdC1qa3Qtand0LW\
lzcy1taXNtYXRjaCJ9.SBdGewXJ5YbbbBIABBzCPUFjAnm3a9IR3pOiUXN05e_7bbTh\
tBiVGfsnLC8GKfUEPUbesrD6a0-aSF22HOwxBA"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Assertion header and payload (signed by jkt-identity-ed25519):

```
{
  "alg": "Ed25519",
  "jwk": {
    "alg": "Ed25519",
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "xMhCrtHXUGjauU2ci3cct0HCofsRTWJmD3kCDC8HQ5A"
  },
  "typ": "jkt-s256+jwt"
}
{
  "cnf": {
    "jwk": {
      "alg": "Ed25519",
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "ge9CgQnrIEclu2brzev1Ve02hk2_S65Fk_2JSD-dIsA"
    }
  },
  "exp": 1800003000,
  "iat": 1799999700,
  "iss": "urn:jkt:sha-256:cXJK0XbcOMrhdbJ52PsaoCUJ0HpIk_C-HaYa6E06kWs",
  "jti": "reject-jkt-jwt-iss-mismatch"
}
```

### reject-cached-unknown-cid

cached member whose cid this verifier never issued. Category 3 (reproduce-the-bytes). Signed by aauth-rust. Expected: reject with `cache_miss` (signature-key lines 1008-1014: cache_miss when a cache identifier cannot be resolved).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig=:rbVsPdcFwwgwG2XNdnC2xBvRTTMAqOT71it318MOdgTIRz+ZzsA\
bzbBbiNCxCZ6rDiWG+OzLyhWBexmTS0/pBg==:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key\
");created=1800000000
Signature-Key: sig=cached;cid="never-issued-0001"

```

Signature base (206 bytes, SHA-256 e88abed8bdd3e0208e041a4eca41a244815e4d50d695e3b371f957c55399be80):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig=cached;cid="never-issued-0001"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

### multi-hwk-jwks

two signatures on one request, sig1 under hwk and sig2 under jwks, both Ed25519; the verifier is configured to verify sig1 and sig2. Category 3 (reproduce-the-bytes). Signed by aauth-rust; aauth-go produced the same bytes. Expected: verify (signature-key lines 173 and 181 leave the labels a verifier checks to application context, so this vector's verifier is configured to verify sig1 and sig2 in place of sig; lines 191 and 199: each signature has its own member keyed by its label, the complete Signature-Key is populated before any signature is created and each signature covers signature-key; line 177: the verifier selects each label's member, and each signature verifies over its own base).

Request:

```http
NOTE: '\' line wrapping per RFC 8792

GET /api/items HTTP/1.1
Host: resource.example
Signature: sig1=:rkrKo/Z0Yr0hokLRnPHNfBdZreQ6MEC3/lysj8HGAI+9wjjSgC\
t8V5M9U2hr3LB04gNge2WCsunRsfiTqHxbBg==:, sig2=:02unbdslIEPAmEcilkFB\
v0EVPLtIjiJlalWYtKpLDZqGgKiophj4Gcp7BJrWEDMpHrIBa+4cVFe1Vd99rTgKBg=\
=:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-ke\
y");created=1800000000, sig2=("@method" "@authority" "@path" "signa\
ture-key");created=1800000000
Signature-Key: sig1=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2br\
zev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519", sig2=jwks;url="https://\
keys.example/signer.jwks";kid="signer-ed25519"

```

Signature base for label `sig1` (hwk, Ed25519, key agent-ed25519; 337 bytes, SHA-256 7f6f6aeaaabab3b3ea74278a703ef86f417eb25d0bd9d4138afb58f1fdd15940):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig1=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2\
brzev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519", sig2=jwks;url="https:\
//keys.example/signer.jwks";kid="signer-ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```

Signature base for label `sig2` (jwks, Ed25519, key signer-ed25519; 337 bytes, SHA-256 7f6f6aeaaabab3b3ea74278a703ef86f417eb25d0bd9d4138afb58f1fdd15940):

```
NOTE: '\' line wrapping per RFC 8792

"@method": GET
"@authority": resource.example
"@path": /api/items
"signature-key": sig1=hwk;kty="OKP";crv="Ed25519";x="ge9CgQnrIEclu2\
brzev1Ve02hk2_S65Fk_2JSD-dIsA";alg="Ed25519", sig2=jwks;url="https:\
//keys.example/signer.jwks";kid="signer-ed25519"
"@signature-params": ("@method" "@authority" "@path" "signature-key\
");created=1800000000
```


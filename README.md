# HTTP Signature-Key Header

This is the working area for the individual Internet-Draft, "HTTP Signature-Key Header".

* [Editor's Copy](https://dickhardt.github.io/signature-key/draft-hardt-httpbis-signature-key.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-hardt-httpbis-signature-key)
* [Compare Editor's Copy to Individual Draft](https://dickhardt.github.io/signature-key/#go.draft-hardt-httpbis-signature-key.diff)

## Abstract

This document defines five HTTP header fields for use with HTTP Message Signatures as defined in RFC 9421. The Signature-Key request header distributes public keys used to verify signatures, with eight initial key distribution schemes: pseudonymous inline keys (hwk), self-issued key delegation via JWK Thumbprint JWTs (jkt-jwt), identified signers with JWKS URI discovery (jwks_uri), direct JWKS fetch (jwks), JWT-based delegation (jwt), self-issued JWTs (self-jwt), X.509 certificate chains (x509), and references to previously cached assertions (cached). The Accept-Signature-Scheme and Accept-Signature-Alg response headers state the schemes and algorithms a server accepts, so a client can select both before it signs. The Signature-Error response header provides structured error information when signature verification fails, and the Signature-Key-Cache response header issues a cache identifier by which a caller can reference a previously presented assertion instead of resending it. Together, these mechanisms enable flexible trust models ranging from privacy-preserving pseudonymous verification to horizontally-scalable delegated authentication and PKI-based identity chains.

## Additional Resources

* [Explainer Document](explainer.md) - Detailed explanation, use cases, and examples

## Contributing

See the [guidelines for contributions](https://github.com/dickhardt/signature-key/blob/main/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.

## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed. See [the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).

## Authors

- Dick Hardt (Hellō)

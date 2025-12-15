# HTTP Signature-Key Header

This is the working area for the individual Internet-Draft, "HTTP Signature-Key Header".

* [Editor's Copy](https://dickhardt.github.io/signature-key/draft-hardt-httpbis-signature-key.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-hardt-httpbis-signature-key)
* [Compare Editor's Copy to Individual Draft](https://dickhardt.github.io/signature-key/#go.draft-hardt-httpbis-signature-key.diff)

## Abstract

This document defines the Signature-Key HTTP header field for distributing public keys used to verify HTTP Message Signatures as defined in RFC 9421. The header supports four key distribution schemes: pseudonymous inline keys (hwk), identified signers with JWKS discovery (jwks), X.509 certificate chains (x509), and JWT-based delegation (jwt). These schemes enable flexible trust models ranging from privacy-preserving anonymous verification to PKI-based identity chains and horizontally-scalable delegated authentication.

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

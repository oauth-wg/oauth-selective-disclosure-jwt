# SD-JWT: Selective Disclosure for JWTs

This is the working area for the IETF [OAUTH Working Group](https://datatracker.ietf.org/wg/oauth/documents/) Internet-Draft, "Selective Disclosure for JWTs (SD-JWT)".

* [Editor's Copy](https://oauth-wg.github.io/oauth-selective-disclosure-jwt/#go.draft-ietf-oauth-selective-disclosure-jwt.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt)
* [Working Group Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt)
* [Compare Editor's Copy to Working Group Draft](https://oauth-wg.github.io/oauth-selective-disclosure-jwt/#go.draft-ietf-oauth-selective-disclosure-jwt.diff)


## Contributing

See the
[guidelines for contributions](https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/master/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.


# Building the Examples & Draft

All examples in the document are created from actual running code maintained at [openwallet-foundation-labs/sd-jwt-python](https://github.com/openwallet-foundation-labs/sd-jwt-python).


To build formatted text and HTML versions of the draft, run the following steps:

 - Follow the instructions in https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md to setup the build environment.
 - Install the sd-jwt library as described in https://github.com/openwallet-foundation-labs/sd-jwt-python
   **or**\
   if the library was installed previously, make sure to enter the virtualenv (`source venv/bin/activate`)
 - `cd examples` to change to the examples directory
 - `sd-jwt-generate example` to generate the examples
 - `cd ..`


Now, the draft can be compiled using `make`.

The artifacts generated for the examples (e.g., serialized SD-JWTs, Disclosures, payloads, etc.) can be inspected in the subdirectories of the `examples` directory.


# SD-JWT Implementations

 * Python: [Reference/Demo Implementation](https://github.com/openwallet-foundation-labs/sd-jwt-python)
 * Kotlin: [SD-JWT-Kotlin (ID Union)](https://github.com/IDunion/SD-JWT-Kotlin)
 * Kotlin: [eudi-lib-jvm-sdjwt (EU Digital Identity Wallet)](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-sdjwt-kt)
 * Swift: [eudi-lib-sdjwt-swift (EU Digital Identity Wallet)](https://github.com/eu-digital-identity-wallet/eudi-lib-sdjwt-swift)
 * Rust: [sd_jwt](https://github.com/kushaldas/sd_jwt)
 * TypeScript: [sd-jwt-js](https://github.com/openwallet-foundation-labs/sd-jwt-js)
 * TypeScript: [sd-jwt](https://github.com/christianpaquin/sd-jwt)
 * TypeScript: [sd-jwt-ts](https://github.com/chike0905/sd-jwt-ts)
 * TypeScript: [jwt-sd](https://github.com/blu3beri/jwt-sd)
 * TypeScript: [@meeco/sd-jwt (Meeco)](https://github.com/meeco/sd-jwt)
 * Java: [Java Library for SD-JWT (Authlete)](https://github.com/authlete/sd-jwt)
 * Go: [sd-jwt (TBD)](https://github.com/TBD54566975/ssi-sdk/tree/main/sd-jwt)
 * Go: [go-sd-jwt](https://github.com/MichaelFraser99/go-sd-jwt)

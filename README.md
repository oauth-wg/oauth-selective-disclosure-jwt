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


## Running SD-JWT PoC

All examples in the document are created from [actual running code](sd_jwt/bin/sd_jwt). To run this code, install sd_jwt:
```
pip3 install .
```

You can read the inline documentation:
````
sd_jwt -h
````

You can then run the code (from the root of this repository):
```
sd_jwt sd_jwt/examples/simple.yml
sd_jwt sd_jwt/examples/simple_structured.yml
sd_jwt sd_jwt/examples/complex.yml
```

You can create your custom setting file creating a folder with a copy of
[sd_jwt/demo_settings.py](sd_jwt/demo_settings.py) renamed to `settings.py`
and a `__init__.py` in it. Then run `sd_jwt` specifying the custom settings path:

````
sd_jwt sd_jwt/examples/simple.yml --settings-path ./custom_settings/
````

## Updating Examples

To update the examples in [draft-ietf-oauth-selective-disclosure-jwt.md](draft-ietf-oauth-selective-disclosure-jwt.md), use the provided script:
```
./update-all-examples.sh
```

It calls the demos with the switch `--replace-examples-in` to replace the example code in
[draft-ietf-oauth-selective-disclosure-jwt.md](draft-ietf-oauth-selective-disclosure-jwt.md) and `--no-randomness` to ensure that the examples are always
generated in the same way (this minimizes the changes that need to be tracked).

The code creates a backup before modifying [draft-ietf-oauth-selective-disclosure-jwt.md](draft-ietf-oauth-selective-disclosure-jwt.md) in [draft-ietf-oauth-selective-disclosure-jwt.bak](draft-ietf-oauth-selective-disclosure-jwt.bak).



## Command Line Usage

To build the HTML version locally, instead of using the GitHub Action, you can use `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).


# Implementations

 * Python: [Reference/Demo Implementation](https://github.com/oauthstuff/draft-selective-disclosure-jwt)
 * Kotlin: [SD-JWT-Kotlin (ID Union)](https://github.com/IDunion/SD-JWT-Kotlin)
 * Rust: [sd_jwt](https://github.com/kushaldas/sd_jwt)
 * TypeScript: [sd-jwt](https://github.com/christianpaquin/sd-jwt)
 * TypeScript: [sd-jwt-ts](https://github.com/chike0905/sd-jwt-ts)
 * Java: [Java Library for SD-JWT (Authlete)](https://github.com/authlete/sd-jwt)
 * Go: [sd-jwt (TBD)](https://github.com/TBD54566975/ssi-sdk/tree/main/sd-jwt)

%%%
title = "Selective Disclosure JWT (SD-JWT)"
abbrev = "oauth-selective-disclosure-jwt"
ipr = "trust200902"
area = "Security"
workgroup = "Web Authorization Protocol"
keyword = ["security", "oauth2"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-fett-selective-disclosure-jwt-00"
stream = "IETF"
status = "standard"

[[author]]
initials="D."
surname="Fett"
fullname="Daniel Fett"
organization="yes.com"
    [author.address]
    email = "mail@danielfett.de"
    uri = "https://danielfett.de/"


[[author]]
initials="K."
surname="Yasuda"
fullname="Kristina Yasuda"
organization="Microsoft"
    [author.address]
    email = "Kristina.Yasuda@microsoft.com"

        
    
%%%

.# Abstract 

This document specifies conventions for creating JSON Web Token (JWT)
documents that support selective disclosure of claim values. 

{mainmatter}

# Introduction {#Introduction}

The JSON-based content of signed JSON Web Token documents as defined in
[@!RFC7515] is secured against modification using digital signatures. A consumer
of a JWT document that has checked the document's signature can safely assume
that the contents of the document have not been modified.  However, anyone
receiving a JWT can read all contents of the document. 

A common use case is that the signed document represents a user's
identity credential, created by an issuer. The issuer includes the user's public
key or a reference thereto. To prove their identity to a verifier, the user can
then send the issuer-signed credential plus a signature over some
transaction-specific values, the so-called proof. It is signed using the user's
private key. This demonstrates possession of the private key, and by extension,
the identity of the user. 

A problem with this approach is that the user has to release the full
issuer-signed credential to the verifier. The credential is often created once
and can then be used for many transactions. Thus, it is in the user's interest
that the credential creates many user attributes which can be disclosed
selectively to verifiers.

This document describes a format for JWT documents that support selective
disclosure (SD-JWT) including a format for proofs, here called releases (SD-JWT-R).

It is important to note that while user identity credentials of natural persons
are common use cases, the mechanisms defined in this document can be used for
any other use case as well. 

## Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they
appear in all capitals, as shown here.

BASE64URL denotes the URL-safe Base64 encoding without padding as defined in
[@!RFC7515], Section 2.

# Terminology

 * A **SD-JWT** is a signed JWT [@!RFC7515], i.e., a JWS, that contains claims
   in a hashed format described in this document and therefore supports
   selective disclosure.
 * A **release** (SD-JWT-R) is a document that contains a subset of the claim
   values of an SD-JWT in plain-text format. It further contains salt values,
   enabling a verifier to check that the plain-text claim values map to the
   hashed claim values in the SD-JWT. If holder binding is desired, the release is
   signed by the holder. 
 * **Holder binding** means that the SD-JWT contains a public key or a reference
   to a public key such that a holder can prove knowledge of the matching
   private key.
 * An **issuer** is the entity that creates a SD-JWT.
 * A **holder** has control over a SD-JWT and, if holder binding is desired, the
   private key for the public key contained in the SD-JWT.
 * A **verifier** checks, upon receiving a SD-JWT and a matching release from a
   holder, that the SD-JWT was issued for the holder (if holder binding is
   desired) and can extract claims from the SD-JWT as far as their values have
   been released by the holder.

# Concept

In the following, the concept of SD-JWTs and releases is described on a
conceptual level.

## Creating a SD-JWT

An SD-JWT, at its core, is a signed document containing some metadata,
optionally the holder's public key, and hashed and salted claims. It is signed
using the issuer's private key.

```
SD-JWT-DOC = (METADATA, HOLDER-PUBLIC-KEY?, HS-CLAIMS)
SD-JWT = SD-JWT-DOC | SIG(SD-JWT-DOC, ISSUER-PRIV-KEY)
```

`HS-CLAIMS` is usually a simple object with claim names mapped to  salted and
hashed claim values:
```
HS-CLAIMS = (
    CLAIM-NAME: HASH(SALT | CLAIM-VALUE)
)*
```

`HS-CLAIMS` can also be nested deeper to capture more complex objects, as will be shown later.

The SD-JWT is sent from the issuer to the holder, together with the plain-text claim values, the salt values, and potentially some other information. 

## Creating a Release

To release claim values to a verifier, a holder creates a document such as the
following:

```
RELEASE-DOC = (METADATA, SALTS)
RELEASE = RELEASE-DOC | SIG(RELEASE-DOC, HOLDER-PRIV-KEY)?
```

Note that the signature over `RELEASE-DOC` is optional and required if, and only
if, holder binding is desired.

`SALTS` is usually a simple object with claim names mapped to values and salts:

```
SALTS = (
    CLAIM-NAME: (DISCLOSED-SALT, DISCLOSED-VALUE)
)
```

Just as `HS-CLAIMS`, `SALTS` can be more complex as well.

The release document is sent together with the SD-JWT from the holder to the
verifier.

## Verifying a Proof

A verifier checks that 

 * if holder binding is desired, the `RELEASE` was signed by
the private key belonging to the public key contained in `SD-JWT-DOC`,
 *  for each claim in `RELEASE`, the hash `HASH(DISCLOSED-SALT | DISCLOSED-VALUE)` matches the hash under the given claim name in the SD-JWT.

The detailed algorithm is described below.

# Data Formats
## SD-JWT Format

An SD-JWT is a JWT signed using the issuer's private key. 

### Payload

#### Selective Disclosure Claims

The claims that are
made available for selective disclosure form a JSON object under the property
`sd_claims`, with the values hashed. 

For each claim value, an individual salt value MUST be chosen such that it
contains at least 128 bits of pseudorandom data, making it hard for an attacker
to guess the salt value.  The salt value MUST then be encoded as a string. It is
RECOMMENDED to BASE64URL encode at least 16 pseudorandom bytes.

The hashes are built by hashing over string that is formed by JSON-encoding an
array containing the salt and the claim value, e.g.: `["6qMQvRL5haj","Peter"]`.
The hash value is then BASE64URL encoded. Note
that the precise JSON encoding can vary, and therefore, the JSON encodings MUST
be sent to the holder along with the SD-JWT, as described below.

#### Holder Public Key

If the issuer wants to enable holder binding, it includes a public key
associated with the holder, or a reference thereto. 

It is out of the scope of this document to describe how the holder key pair is
established. For example, the issuer MAY create the key pair for the holder or
holder and issuer MAY use pre-established key material.

#### Other Claims

The SD-JWT payload typically contains other claims, such as `iss`, `iat`, etc. 

### Example

In the following examples, these claims are the payload of the SD-JWT:

{#example-sd-jwt-claims}
```json
{
    "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
    "given_name": "John",
    "family_name": "Doe",
    "email": "johndoe@example.com",
    "phone_number": "+1-202-555-0101",
    "address": {
        "street_address": "123 Main St",
        "locality": "Anytown",
        "region": "Anystate",
        "country": "US"
    },
    "birthdate": "1940-01-01"
}
```

The following shows the resulting SD-JWT payload:

{#example-sd-jwt-payload}
```json
{
    "iss": "https://example.com/issuer",
    "sub_jwk": {
        "kty": "RSA",
        "n": "7swmcr5Nh9iJRg_9BmWNj2QKJ826K-WfTxSHjomQhwvX4t94V68Oe3es35y5mOawaf0v8Ktc40VpP5t3CHcQHpCH-Ht_r2vz75IayPwoCCuaYUEgoAPh0c3_12rqhVUd2VInDqlUY9mhWNTq3e9LH9wVehqVcBC2cV8MeNQa3oI7WuHC9r4REXLJOoqWoIx09D1SIcC1t3le99ETFJzwoFDgR5cfeIKq9Ccm9Y9HFasuDJwjzn0hMAmP5_-cRCtzkN9d9J9Ud1agJ17_QGEvxB7laqI5kDV_CflrZlarYbJWtPPbl8eAbOwDYwz0KtZbDafRL2FXUaLcQwkpxmcmGw",
        "e": "AQAB"
    },
    "iat": 1516239022,
    "exp": 1516247022,
    "sd_claims": {
        "sub": "7C3a4gmoVNLFH8CT0ZaVMZyZWv7_8BwUwkbPrA9rlvc",
        "given_name": "Ue0F83URdYtaLYtddjgBD7wqDzVm2IYmEhyy2kX_EpQ",
        "family_name": "D8xO8GBLv0OYnIBCRiLX8GRC42WEUxK5APqpN1GXYIs",
        "email": "B5FAqIgtytJ_R9nI6dPsXj4qYjMWy-Mumqxh_ThjGTo",
        "phone_number": "MhHhzKpYVFRg95qxWwH2hutImbSjbbrK-E7rPHA-9dI",
        "address": "8hL1eJbfkk5VK1288cxt1aPuwWaV07Q50K9eIUgpvf4",
        "birthdate": "lkcZg7hHk5zSfTbkPeeCxbXaIOANJaJk0EF2_qMRBnQ"
    }
}
```

The SD-JWT is then signed by the issuer to create a document like the following:

{#example-sd-jwt-encoded}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogIjdzd21jcjVOaDlpSlJnXzlCb
VdOajJRS0o4MjZLLVdmVHhTSGpvbVFod3ZYNHQ5NFY2OE9lM2VzMzV5NW1PYXdhZjB2OEt
0YzQwVnBQNXQzQ0hjUUhwQ0gtSHRfcjJ2ejc1SWF5UHdvQ0N1YVlVRWdvQVBoMGMzXzEyc
nFoVlVkMlZJbkRxbFVZOW1oV05UcTNlOUxIOXdWZWhxVmNCQzJjVjhNZU5RYTNvSTdXdUh
DOXI0UkVYTEpPb3FXb0l4MDlEMVNJY0MxdDNsZTk5RVRGSnp3b0ZEZ1I1Y2ZlSUtxOUNjb
TlZOUhGYXN1REp3anpuMGhNQW1QNV8tY1JDdHprTjlkOUo5VWQxYWdKMTdfUUdFdnhCN2x
hcUk1a0RWX0NmbHJabGFyWWJKV3RQUGJsOGVBYk93RFl3ejBLdFpiRGFmUkwyRlhVYUxjU
XdrcHhtY21HdyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAic2RfY2xhaW1zIjogeyJzdWIiOiAiN0MzYTRnbW9WTkxGSDhDVDBaY
VZNWnlaV3Y3XzhCd1V3a2JQckE5cmx2YyIsICJnaXZlbl9uYW1lIjogIlVlMEY4M1VSZFl
0YUxZdGRkamdCRDd3cUR6Vm0ySVltRWh5eTJrWF9FcFEiLCAiZmFtaWx5X25hbWUiOiAiR
Dh4TzhHQkx2ME9ZbklCQ1JpTFg4R1JDNDJXRVV4SzVBUHFwTjFHWFlJcyIsICJlbWFpbCI
6ICJCNUZBcUlndHl0Sl9SOW5JNmRQc1hqNHFZak1XeS1NdW1xeGhfVGhqR1RvIiwgInBob
25lX251bWJlciI6ICJNaEhoektwWVZGUmc5NXF4V3dIMmh1dEltYlNqYmJySy1FN3JQSEE
tOWRJIiwgImFkZHJlc3MiOiAiOGhMMWVKYmZrazVWSzEyODhjeHQxYVB1d1dhVjA3UTUwS
zllSVVncHZmNCIsICJiaXJ0aGRhdGUiOiAibGtjWmc3aEhrNXpTZlRia1BlZUN4YlhhSU9
BTkphSmswRUYyX3FNUkJuUSJ9fQ.vTgjWNzQ51EntAEUtmvNfcbykArEHz0ny7KriGNFXC
mRphysAXlF4itOg-94b6tQIPZT-vNQQWXlFMxjfzN9j_qIfuq39nKt9CSmCtA-wEEeMSlA
TQB1YHVvVHHwof3nJnSZdW2B4m3Tf7fu2r9Ul0RasNVGr25zX-wHwjol6Rh3vJuxTeFBlZ
_btA2fhngpUBg-G7bHGyrQ44nQJ8cpjomJUEZpANLV8ds1N7-iKVwDPqE6dd-AH5EqbTd7
-Ofis3LTFz995TU4j1a_I4_hrrxzYkuanCSUrCUuxJVRZBj75gD6Iy_6KEMKaT2iCpg1N5
xc1uMF2qe_QB_BJPt_hg.ewogICAgInNkX2NsYWltcyI6IHsKICAgICAgICAic3ViIjogI
ltcIk0wUlhRdi1ia01TWmVvTjhXT0xvRVFcIiwgXCI2YzVjMGE0OS1iNTg5LTQzMWQtYmF
lNy0yMTkxMjJhOWVjMmNcIl0iLAogICAgICAgICJnaXZlbl9uYW1lIjogIltcImxLbUlxZ
G1PajBlb1J0a0Q5YXhJZHdcIiwgXCJKb2huXCJdIiwKICAgICAgICAiZmFtaWx5X25hbWU
iOiAiW1wiMjh0dWQ2R0Y2YUE5U1k2dWo0MkV1QVwiLCBcIkRvZVwiXSIsCiAgICAgICAgI
mVtYWlsIjogIltcImY4TUhab2ZUWEx0d2R4dUU3bXVpTHdcIiwgXCJqb2huZG9lQGV4YW1
wbGUuY29tXCJdIiwKICAgICAgICAicGhvbmVfbnVtYmVyIjogIltcIlVseFBQdm1HRV9EQ
XNJX21rMmJhNFFcIiwgXCIrMS0yMDItNTU1LTAxMDFcIl0iLAogICAgICAgICJhZGRyZXN
zIjogIltcIlFtcVpWSUZLbU44X3VaNGNNZ2ZsdndcIiwge1wic3RyZWV0X2FkZHJlc3NcI
jogXCIxMjMgTWFpbiBTdFwiLCBcImxvY2FsaXR5XCI6IFwiQW55dG93blwiLCBcInJlZ2l
vblwiOiBcIkFueXN0YXRlXCIsIFwiY291bnRyeVwiOiBcIlVTXCJ9XSIsCiAgICAgICAgI
mJpcnRoZGF0ZSI6ICJbXCIwaXlkd2Z5RU1vLXhrMXpHLXJOZHV3XCIsIFwiMTk0MC0wMS0
wMVwiXSIKICAgIH0KfQ
```

(Line breaks for presentation only.)

## SD-JWT Salt/Value Container

Besides the SD-JWT itself, the holder needs to learn the raw claim values that
are contained in the SD-JWT, along with the precise input to the hash
calculation, and the salts. There MAY be other information the issuer needs to
communicate to the holder, such as a private key key if the issuer selected the
holder key pair.

### Payload

A SD-JWT Salt/Value Container (SVC) is a JSON object containing at least the
top-level property `sd_claims`. Its structure mirrors the one of `sd_claims` in
the SD-JWT, but the values are the inputs to the hash calculations the issuer
used, as strings.

The SVC MAY contain further properties, for example, to transport the holder
private key.

### Example
{#example-svc-payload}
```json
{
    "sd_claims": {
        "sub": "[\"M0RXQv-bkMSZeoN8WOLoEQ\", \"6c5c0a49-b589-431d-bae7-219122a9ec2c\"]",
        "given_name": "[\"lKmIqdmOj0eoRtkD9axIdw\", \"John\"]",
        "family_name": "[\"28tud6GF6aA9SY6uj42EuA\", \"Doe\"]",
        "email": "[\"f8MHZofTXLtwdxuE7muiLw\", \"johndoe@example.com\"]",
        "phone_number": "[\"UlxPPvmGE_DAsI_mk2ba4Q\", \"+1-202-555-0101\"]",
        "address": "[\"QmqZVIFKmN8_uZ4cMgflvw\", {\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}]",
        "birthdate": "[\"0iydwfyEMo-xk1zG-rNduw\", \"1940-01-01\"]"
    }
}
```

## SD-JWT and SVC Combined Format

For transporting the SVC together with the SD-JWT from the issuer to the holder,
the SVC is BASE64URL encoded and appended to the SD-JWT using `.` as the
separator:

{#example-combined-encoded}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly3ayI6IHsT(...)DRyTmXhKNPSJ9fQ.cHNaU6b9hAZ-cdedhfBmw.ewogICAgImdpdmVuX25hbWUiOi(...)MTk0MC0wMS0wMVwiXSIKfQ
```

(Line breaks for presentation only.)

## SD-JWT Release Format

The following shows the contents of a release document:

{#example-release-payload}
```json
{
    "nonce": "B47HtpCpiAqdIp1H3bg4Og",
    "sd_claims": {
        "family_name": "[\"28tud6GF6aA9SY6uj42EuA\", \"Doe\"]",
        "address": "[\"QmqZVIFKmN8_uZ4cMgflvw\", {\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}]"
    }
}
```
For each claim, an array of the salt and the claim value is contained in the
`sd_claims` object. The SD-JWT Release MAY contain further claims, for example, to
ensure a binding to a concrete transaction (in the example the `nonce` and `aud` claims).

If holder binding is desired, the SD-JWT Release is signed by the holder. If no
holder binding is to be used, the `none` algorithm is used, i.e., the document
is not signed.

In any case, the result is encoded as described in [@!RFC7515]:

{#example-release-encoded}
```
eyJhbGciOiAiUlMyNTYifQ.eyJub25jZSI6ICJCNDdIdHBDcGlBcWRJcDFIM2JnNE9nIiw
gInNkX2NsYWltcyI6IHsiZmFtaWx5X25hbWUiOiAiW1wiMjh0dWQ2R0Y2YUE5U1k2dWo0M
kV1QVwiLCBcIkRvZVwiXSIsICJhZGRyZXNzIjogIltcIlFtcVpWSUZLbU44X3VaNGNNZ2Z
sdndcIiwge1wic3RyZWV0X2FkZHJlc3NcIjogXCIxMjMgTWFpbiBTdFwiLCBcImxvY2Fsa
XR5XCI6IFwiQW55dG93blwiLCBcInJlZ2lvblwiOiBcIkFueXN0YXRlXCIsIFwiY291bnR
yeVwiOiBcIlVTXCJ9XSJ9fQ.c7yyFqxEDpIWG93y6l61NVrwnW5EAaD9Rr-Ab6VggclOsc
hN_x7q703TDEG3JsAfWSJroU7pbCOgAXdtx_88T_SDh6daxqbMt_2faRWIF0vjTvuvvGXx
dzfNJit8U-4d_g82Mbjw9kUkouhdDPFo7Z7a6Q4dC8Kn-0PJ5LeMVdRVHIvfotU_EZ6kPD
66VGv_3aPD4KnZuMAbztf-Ng43H6Xvx1KLX0JUd3Fg6jUNmjTVo1s1s5KVYANJ2CkuVQ1f
OhcJG_YF0nyy2X8x3CseC0vl2jYQ7eacqgJrlLEyh0ym15CyF4fzkX8CRC8Res3RUDtQMa
XYMM0E0JM6sredsw
```

(Line breaks for presentation only.)
## Presentation Format

The SD-JWT and the SD-JWT Release can be combined into one document using `.` as a separator:

{#example-release-combined}
```
eyJhbGciOiAiUlMyNTYifQ.eyJub25jZSI6ICJCNDdIdHBDcGlBcWRJcDFIM2JnNE9nIiw
gInNkX2NsYWltcyI6IHsiZmFtaWx5X25hbWUiOiAiW1wiMjh0dWQ2R0Y2YUE5U1k2dWo0M
kV1QVwiLCBcIkRvZVwiXSIsICJhZGRyZXNzIjogIltcIlFtcVpWSUZLbU44X3VaNGNNZ2Z
sdndcIiwge1wic3RyZWV0X2FkZHJlc3NcIjogXCIxMjMgTWFpbiBTdFwiLCBcImxvY2Fsa
XR5XCI6IFwiQW55dG93blwiLCBcInJlZ2lvblwiOiBcIkFueXN0YXRlXCIsIFwiY291bnR
yeVwiOiBcIlVTXCJ9XSJ9fQ.c7yyFqxEDpIWG93y6l61NVrwnW5EAaD9Rr-Ab6VggclOsc
hN_x7q703TDEG3JsAfWSJroU7pbCOgAXdtx_88T_SDh6daxqbMt_2faRWIF0vjTvuvvGXx
dzfNJit8U-4d_g82Mbjw9kUkouhdDPFo7Z7a6Q4dC8Kn-0PJ5LeMVdRVHIvfotU_EZ6kPD
66VGv_3aPD4KnZuMAbztf-Ng43H6Xvx1KLX0JUd3Fg6jUNmjTVo1s1s5KVYANJ2CkuVQ1f
OhcJG_YF0nyy2X8x3CseC0vl2jYQ7eacqgJrlLEyh0ym15CyF4fzkX8CRC8Res3RUDtQMa
XYMM0E0JM6sredsw.eyJhbGciOiAiUlMyNTYifQ.eyJub25jZSI6ICJCNDdIdHBDcGlBcW
RJcDFIM2JnNE9nIiwgInNkX2NsYWltcyI6IHsiZmFtaWx5X25hbWUiOiAiW1wiMjh0dWQ2
R0Y2YUE5U1k2dWo0MkV1QVwiLCBcIkRvZVwiXSIsICJhZGRyZXNzIjogIltcIlFtcVpWSU
ZLbU44X3VaNGNNZ2ZsdndcIiwge1wic3RyZWV0X2FkZHJlc3NcIjogXCIxMjMgTWFpbiBT
dFwiLCBcImxvY2FsaXR5XCI6IFwiQW55dG93blwiLCBcInJlZ2lvblwiOiBcIkFueXN0YX
RlXCIsIFwiY291bnRyeVwiOiBcIlVTXCJ9XSJ9fQ.c7yyFqxEDpIWG93y6l61NVrwnW5EA
aD9Rr-Ab6VggclOschN_x7q703TDEG3JsAfWSJroU7pbCOgAXdtx_88T_SDh6daxqbMt_2
faRWIF0vjTvuvvGXxdzfNJit8U-4d_g82Mbjw9kUkouhdDPFo7Z7a6Q4dC8Kn-0PJ5LeMV
dRVHIvfotU_EZ6kPD66VGv_3aPD4KnZuMAbztf-Ng43H6Xvx1KLX0JUd3Fg6jUNmjTVo1s
1s5KVYANJ2CkuVQ1fOhcJG_YF0nyy2X8x3CseC0vl2jYQ7eacqgJrlLEyh0ym15CyF4fzk
X8CRC8Res3RUDtQMaXYMM0E0JM6sredsw
```

(Line breaks for presentation only.)

# Verification

Verifiers MUST follow [@RFC8725] for checking the SD-JWT and, if signed, the
SD-JWT Release.

A verifier needs to go through (at least) the following steps before
trusting/using any of the contents of an SD-JWT:

 1. Determine if holder binding is to be checked for the SD-JWT. Refer to (#holder_binding_security) for details.
 2. Check that the presentation consists of six `.`-separated elements; if holder binding is not required, the last element can be empty.
 3. Separate the SD-JWT from the SD-JWT Release.
 4. Validate the SD-JWT:
    1. Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [@RFC8725], Sections 3.1 and 3.2 for details.
    2. Validate the signature over the SD-JWT. 
    3. Validate the issuer of the SD-JWT and that the signing key belongs to this issuer.
    4. Check that the SD-JWT is valid using `nbf`, `iat`, and `exp` claims, if provided in the SD-JWT.
    5. Check that the claim `sd_claims` is present in the SD-JWT.
 5. Validate the SD-JWT Release:
    1. If holder binding is required, validate the signature over the SD-JWT using the same steps as for the SD-JWT plus the following steps:
       1. Determine that the public key for the private key that used to sign the SD-JWT Release is bound to the SD-JWT, i.e., the SD-JWT either contains a reference to the public key or contains the public key itself.
       2. Determine that the SD-JWT Release is bound to the current transaction and was created for this verifier (replay protection). This is usually achieved by a `nonce` and `aud` field within the SD-JWT Release.
    2. For each claim that the verifier requires:
       1. Ensure that the claim is present in `sd_claims` both in the SD-JWT and the SD-JWT Release. If `sd_claims` is structured, the claim MUST be present at the same place within the structure.
       2. Check that the BASE64URL encoded hash of the claim value in the SD-JWT Release (which includes the salt and the actual claim value) matches the hash provided in the SD-JWT.
       3. Ensure that the claim value in the SD-JWT Release is a JSON-encoded array of exactly two values.
       4. Store the second of the two values. Once all necessary claims have been verified, it can be validated and used according to the requirements of the application.

If any step fails, the input is not valid and processing MUST be aborted.


# Security Considerations {#security_considerations}

For the security of this scheme, the following properties are required of the hash function:

- Given a claim value, a salt, and the resulting hash, it is hard to find a second salt value so that HASH(salt | claim_value) equals the hash.


## Holder Binding {#holder_binding_security}


# Privacy Considerations {#privacy_considerations}

TBD

# Acknowledgements {#Acknowledgements}
      
We would like to thank ...

# IANA Considerations {#iana_considerations}

TBD

<reference anchor="OIDC" target="https://openid.net/specs/openid-connect-core-1_0.html">
  <front>
    <title>OpenID Connect Core 1.0 incorporating errata set 1</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization>NRI</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization>Ping Identity</organization>
    </author>
    <author initials="M." surname="Jones" fullname="Mike Jones">
      <organization>Microsoft</organization>
    </author>
    <author initials="B." surname="de Medeiros" fullname="Breno de Medeiros">
      <organization>Google</organization>
    </author>
    <author initials="C." surname="Mortimore" fullname="Chuck Mortimore">
      <organization>Salesforce</organization>
    </author>
   <date day="8" month="Nov" year="2014"/>
  </front>
</reference>

{backmatter}

# Additional Examples

# Document History

   [[ To be removed from the final specification ]]

   -00

   *  Renamed to SD-JWT (focus on JWT instead of JWS since signature is optional)
   *  Rename proof to release, since when there is no signature, the term "proof" can be misleading
   *  Improved the structure of the description
   *  Examples generated and placed in main.md using python code


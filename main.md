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

The JSON-based claims in a signed JSON Web Token (JWT) [@!RFC7519] document
are secured against modification using JSON Web Signature (JWS) [@!RFC7515] digital signatures.
A consumer
of a signed JWT document that has checked the document's signature can safely assume
that the contents of the document have not been modified.  However, anyone
receiving an unencrypted JWT can read all of the claims and likewise,
anyone with the decryption key receiving an encrypted JWT
can also read all of the claims.

A common use case is that the signed document represents a user's identity
credential, created by an issuer. The issuer includes the user's public key or a
reference thereto. To prove their identity to a verifier, the user can then send
the issuer-signed credential plus a signature over some transaction-specific
values. This demonstrates possession of the private key, and by extension, the
identity of the user. 

A problem with this approach is that the credential is often created once and
then used for many transactions; it is therefore in the user's interest that the
credential contains many user attributes which can be disclosed selectively to
verifiers. Conversely, since the user has to send the full issuer-signed
credential to the verifier, claims may be disclosed to the verifier that are not
relevant for the use case or should not be disclosed to the verifier for other
reasons. 

To solve this, credentials with "selective disclosure" properties can be used.
They enable a user to release only those claims to the verifier that are
relevant for the use case at hand.

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

 * A **SD-JWT** is a signed JWT [@!RFC7519], i.e., a JWS [@!RFC7515], that contains claims
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

The claims that are made available for selective disclosure form a JSON object
under the property `sd_claims`, with the values hashed. 

The object can be a 'flat' object, directly containing all claim names and
hashed claim values without any deeper structure. The object can also be a
structured object, where some claims and their respective hashes are contained
in places deeper in the structure. It is up to the issuer to decide how to
structure the representation such that it is suitable for the use case. Examples
1 and 2 below show this using the [@OIDC] `address` claim, a structured claim.
Appendix 1 shows a more complex example using claims from eKYC (todo:
reference).

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

### Example 1 - Flat SD-JWT

This example shows a simple SD-JWT containing user claims. The issuer here
decided to use a completely flat structure, i.e., the `address` claim can only
be disclosed in full.

In this example, these claims are the payload of the SD-JWT:

{#example-simple-sd-jwt-claims}
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

{#example-simple-sd-jwt-payload}
```json
{
  "iss": "https://example.com/issuer",
  "sub_jwk": {
    "kty": "RSA",
    "n": "1RYRKBNFg1H_MoiB8boAI6RgEE1iYOUVTCST_2roeDzTf40IBNraG3eyD_N2la6CgK2QFud2dxjXuNkKW5HsU63J-sR46A1c4hMA1Lcij_RfYo9JgUQAWSfmxSCIephIywiVOwTgxPRJxbISTAwD16m9udGbAhP2wMVoLxWwAEPLcEF6MZwVZ0W7ED9NRKFTJWff4M481Y867tZHmfaVaacBep_BAc1d4TOBRQLCtFz5PU94rYoTA3-Yt7wlINsSmGbOndQ-nYg0FZRp3R-Lzi-hfS98ZLD-6-Pyqu9YCH-8ewugxGxBqNFTeWAquAq3lVUIcP1otP14t6bxP9l6xw",
    "e": "AQAB"
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "sd_claims": {
    "sub": "ZL4ST6jC1ENkBlA6xUNovTGh_2jO7GRHfxbtAzg5k1M",
    "given_name": "Vlzc_oP3BzB3jlQBI2U_XKCWMXkkkvqPnx-q9QkZYUg",
    "family_name": "a_vV9dL1Mp1vDkzDV9SBARSlIQm4km3fdwkULMwVdq4",
    "email": "GBd77QqhxZYnKkjUIhl5ZcU1yLLffO_iLrfeJNvg72Y",
    "phone_number": "kaYJNs7f_CDxHcl295d1Qt8wcuuUQKTMFllX2MGVhOo",
    "address": "VK-LE9viUaLpEXpGhger4JDL0FH2h6EBV26Cp6-Bdzc",
    "birthdate": "Qj3M24ZWu_uFddgch0yMtc2hEy8uQTDJny-lVwd_0J0"
  }
}
```

The SD-JWT is then signed by the issuer to create a document like the following:

{#example-simple-sd-jwt-encoded}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogIjFSWVJLQk5GZzFIX01vaUI4Y
m9BSTZSZ0VFMWlZT1VWVENTVF8ycm9lRHpUZjQwSUJOcmFHM2V5RF9OMmxhNkNnSzJRRnV
kMmR4alh1TmtLVzVIc1U2M0otc1I0NkExYzRoTUExTGNpal9SZllvOUpnVVFBV1NmbXhTQ
0llcGhJeXdpVk93VGd4UFJKeGJJU1RBd0QxNm05dWRHYkFoUDJ3TVZvTHhXd0FFUExjRUY
2TVp3VlowVzdFRDlOUktGVEpXZmY0TTQ4MVk4Njd0WkhtZmFWYWFjQmVwX0JBYzFkNFRPQ
lJRTEN0Rno1UFU5NHJZb1RBMy1ZdDd3bElOc1NtR2JPbmRRLW5ZZzBGWlJwM1ItTHppLWh
mUzk4WkxELTYtUHlxdTlZQ0gtOGV3dWd4R3hCcU5GVGVXQXF1QXEzbFZVSWNQMW90UDE0d
DZieFA5bDZ4dyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAic2RfY2xhaW1zIjogeyJzdWIiOiAiWkw0U1Q2akMxRU5rQmxBNnhVT
m92VEdoXzJqTzdHUkhmeGJ0QXpnNWsxTSIsICJnaXZlbl9uYW1lIjogIlZsemNfb1AzQnp
CM2psUUJJMlVfWEtDV01Ya2trdnFQbngtcTlRa1pZVWciLCAiZmFtaWx5X25hbWUiOiAiY
V92VjlkTDFNcDF2RGt6RFY5U0JBUlNsSVFtNGttM2Zkd2tVTE13VmRxNCIsICJlbWFpbCI
6ICJHQmQ3N1FxaHhaWW5La2pVSWhsNVpjVTF5TExmZk9faUxyZmVKTnZnNzJZIiwgInBob
25lX251bWJlciI6ICJrYVlKTnM3Zl9DRHhIY2wyOTVkMVF0OHdjdXVVUUtUTUZsbFgyTUd
WaE9vIiwgImFkZHJlc3MiOiAiVkstTEU5dmlVYUxwRVhwR2hnZXI0SkRMMEZIMmg2RUJWM
jZDcDYtQmR6YyIsICJiaXJ0aGRhdGUiOiAiUWozTTI0Wld1X3VGZGRnY2gweU10YzJoRXk
4dVFUREpueS1sVndkXzBKMCJ9fQ.T60iDKReljcIRl0Dkn_RtdbSF-014aKSq2F7Wn7G8Q
ZNThM09lV6i5GsevTFNTEDSecx7iJjD8_jW94ug0-gYzLqFRneyN8vmnSUaHJKmbd4jEx1
_Vh9iH-eCdMtTo3UYjwYLt3fAQRrU9iRi4Z7wAbvWYOOf1bHtWR0VF9F1SrZ74gIgA5CFi
b1EXG3r3pMJwXNTV041tdZn3EhMUOlfElcBy5UhxiISoaB2COJNJKIEzc94OSJ42vg2_nd
wAzNiF8HXYQCklHqA0W_xxx6BCN3cIMQOHvv2PMf-33T5WqWtzQb6jPW0G919liomtw4Fm
Zn0nT9n8N9PfyibNuWww.ewogICAgInNkX2NsYWltcyI6IHsKICAgICAgICAic3ViIjogI
ltcInlwam92Zl9wTXBWUnBXdU5sa0VRWndcIiwgXCI2YzVjMGE0OS1iNTg5LTQzMWQtYmF
lNy0yMTkxMjJhOWVjMmNcIl0iLAogICAgICAgICJnaXZlbl9uYW1lIjogIltcIkhOUUdRM
2hlNElOeENEZFExRUJZOVFcIiwgXCJKb2huXCJdIiwKICAgICAgICAiZmFtaWx5X25hbWU
iOiAiW1wiWGFLS19Cc2JKbWp2bVYydGxNR0lQQVwiLCBcIkRvZVwiXSIsCiAgICAgICAgI
mVtYWlsIjogIltcIkxkZThlOUY1MkhPMmo1NHBPODEwVUFcIiwgXCJqb2huZG9lQGV4YW1
wbGUuY29tXCJdIiwKICAgICAgICAicGhvbmVfbnVtYmVyIjogIltcIm1wTlR2a2dWM2txR
mUxaVlvakQ3aHdcIiwgXCIrMS0yMDItNTU1LTAxMDFcIl0iLAogICAgICAgICJhZGRyZXN
zIjogIltcImttX24yc0VXcHE0ZFp6NEctVGpaekFcIiwge1wic3RyZWV0X2FkZHJlc3NcI
jogXCIxMjMgTWFpbiBTdFwiLCBcImxvY2FsaXR5XCI6IFwiQW55dG93blwiLCBcInJlZ2l
vblwiOiBcIkFueXN0YXRlXCIsIFwiY291bnRyeVwiOiBcIlVTXCJ9XSIsCiAgICAgICAgI
mJpcnRoZGF0ZSI6ICJbXCJHTzVTUVJ6Znp1T25IT0U1YndUTEd3XCIsIFwiMTk0MC0wMS0
wMVwiXSIKICAgIH0KfQ
```

(Line breaks for presentation only.)

### Example 2 - Structured SD-JWT

In this example, the issuer decided to create a structured object for the
hashes. This allows for the release of individual members of the address claim
separately.

The user claims are as in Example 1 above. The resulting SD-JWT payload is as follows:

{#example-simple_structured-sd-jwt-payload}
```json
{
  "iss": "https://example.com/issuer",
  "sub_jwk": {
    "kty": "RSA",
    "n": "ucQKEVgEZ6H9siztJ6V2t-FdWZtXkM3KiEGOKR2Wi703E4quZY4oYAsrGP7P-jKZ6Dgx_OnzsPKxuWdVr7ahttH2ysaOqdrX-xhAxZaO9MwSZX5ZdSHSRWtymXV3GPzmNelpIfeMqFO7wAE042FCxH_nHrfc_ftoCT6Y3aGrXzEEBtp_Y186hXKI-4HmRp9eLuHnI6EaV2gArmk5YiH6kBqxpRasNqH3GqXjW-r4BogCHGmM7_QaZBpagbg63ggRIjV2CAJOw5ft9cguWe0rlvDkaf5znwu2Di4VlRSNjz4Gsfd8l8PoFMts9MG4riUscMz_FhjxR-Pf2INl3CnNxQ",
    "e": "AQAB"
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "sd_claims": {
    "sub": "GO32536jKNeRtQ8_QY6kjrUSn-xuO9tB5TKv1-OtFLQ",
    "given_name": "1qoEuCtvGoDbaGPLYfAXSSye3UfhsKX1kB_vjm-ZiPA",
    "family_name": "i1dd_PbnYd3T5_asnAHOpkoD6r7-oaoS1aGbJZ2hfls",
    "email": "2k4HJJJQECNSua9rWTo3_RIx-vgB6fRCeghOpYA6iRU",
    "phone_number": "9Qi70t6PDDJ3opcv-WDqtuoieWQ-PtC2Zm-R5-7G5qU",
    "address": {
      "street_address": "dqrQwg2hzGiCS-H3WLJnCYFNDIcAmmglBmiOl1d22Fw",
      "locality": "Ci3wFQm0BJN_MS1xQKu0d3xYhFtSrKBtpYEFivazVnM",
      "region": "89mgTbBTpwye48Hob6MtXlkzmu4q19glpstPDkL2Zb4",
      "country": "uo4HK7hTC182WtnKCULs2fY_nmkfLjhWtBZTfe2RwO8"
    },
    "birthdate": "c9xlkS9heumCeMbHnWCg_GvMEi82TLx-6cTNhEkYN-I"
  }
}
```

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

### Example 1 - SVC for a Flat SD-JWT

The SVC for Example 1 is as follows:

{#example-simple-svc-payload}
```json
{
  "sd_claims": {
    "sub": "[\"ypjovf_pMpVRpWuNlkEQZw\", \"6c5c0a49-b589-431d-bae7-219122a9ec2c\"]",
    "given_name": "[\"HNQGQ3he4INxCDdQ1EBY9Q\", \"John\"]",
    "family_name": "[\"XaKK_BsbJmjvmV2tlMGIPA\", \"Doe\"]",
    "email": "[\"Lde8e9F52HO2j54pO810UA\", \"johndoe@example.com\"]",
    "phone_number": "[\"mpNTvkgV3kqFe1iYojD7hw\", \"+1-202-555-0101\"]",
    "address": "[\"km_n2sEWpq4dZz4G-TjZzA\", {\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}]",
    "birthdate": "[\"GO5SQRzfzuOnHOE5bwTLGw\", \"1940-01-01\"]"
  }
}
```

### Example 2 - SVC for a Structured SD-JWT

The SVC for Example 2 is as follows:

{#example-simple_structured-svc-payload}
```json
{
  "sd_claims": {
    "sub": "[\"WNYi4d0w7jkR-vJqso20ug\", \"6c5c0a49-b589-431d-bae7-219122a9ec2c\"]",
    "given_name": "[\"7wPIFvwTg7rNCj8Jv2AXLQ\", \"John\"]",
    "family_name": "[\"jUDKEqq2KxVz3rMNP80d6w\", \"Doe\"]",
    "email": "[\"V5-EN48tsQI5J0x-QkjNWA\", \"johndoe@example.com\"]",
    "phone_number": "[\"ZAyrr0dKsjdydhziY_SgKQ\", \"+1-202-555-0101\"]",
    "address": {
      "street_address": "[\"b-O1rXGn7yCHi2rNhJjauQ\", \"123 Main St\"]",
      "locality": "[\"_iweFrWgVIEUmaf1TezIyg\", \"Anytown\"]",
      "region": "[\"9Z7AlXqp_RGYj7TsXhUZ3g\", \"Anystate\"]",
      "country": "[\"G5I-b8-ImhlbZBMIJKgTPg\", \"US\"]"
    },
    "birthdate": "[\"7eSFThfsoMysrP4CvUlBnQ\", \"1940-01-01\"]"
  }
}
```


## SD-JWT and SVC Combined Format

For transporting the SVC together with the SD-JWT from the issuer to the holder,
the SVC is BASE64URL encoded and appended to the SD-JWT using `.` as the
separator. For Example 1, the combined format looks as follows:

{#example-simple-combined-encoded}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogIjFSWVJLQk5GZzFIX01vaUI4Y
m9BSTZSZ0VFMWlZT1VWVENTVF8ycm9lRHpUZjQwSUJOcmFHM2V5RF9OMmxhNkNnSzJRRnV
kMmR4alh1TmtLVzVIc1U2M0otc1I0NkExYzRoTUExTGNpal9SZllvOUpnVVFBV1NmbXhTQ
0llcGhJeXdpVk93VGd4UFJKeGJJU1RBd0QxNm05dWRHYkFoUDJ3TVZvTHhXd0FFUExjRUY
2TVp3VlowVzdFRDlOUktGVEpXZmY0TTQ4MVk4Njd0WkhtZmFWYWFjQmVwX0JBYzFkNFRPQ
lJRTEN0Rno1UFU5NHJZb1RBMy1ZdDd3bElOc1NtR2JPbmRRLW5ZZzBGWlJwM1ItTHppLWh
mUzk4WkxELTYtUHlxdTlZQ0gtOGV3dWd4R3hCcU5GVGVXQXF1QXEzbFZVSWNQMW90UDE0d
DZieFA5bDZ4dyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAic2RfY2xhaW1zIjogeyJzdWIiOiAiWkw0U1Q2akMxRU5rQmxBNnhVT
m92VEdoXzJqTzdHUkhmeGJ0QXpnNWsxTSIsICJnaXZlbl9uYW1lIjogIlZsemNfb1AzQnp
CM2psUUJJMlVfWEtDV01Ya2trdnFQbngtcTlRa1pZVWciLCAiZmFtaWx5X25hbWUiOiAiY
V92VjlkTDFNcDF2RGt6RFY5U0JBUlNsSVFtNGttM2Zkd2tVTE13VmRxNCIsICJlbWFpbCI
6ICJHQmQ3N1FxaHhaWW5La2pVSWhsNVpjVTF5TExmZk9faUxyZmVKTnZnNzJZIiwgInBob
25lX251bWJlciI6ICJrYVlKTnM3Zl9DRHhIY2wyOTVkMVF0OHdjdXVVUUtUTUZsbFgyTUd
WaE9vIiwgImFkZHJlc3MiOiAiVkstTEU5dmlVYUxwRVhwR2hnZXI0SkRMMEZIMmg2RUJWM
jZDcDYtQmR6YyIsICJiaXJ0aGRhdGUiOiAiUWozTTI0Wld1X3VGZGRnY2gweU10YzJoRXk
4dVFUREpueS1sVndkXzBKMCJ9fQ.T60iDKReljcIRl0Dkn_RtdbSF-014aKSq2F7Wn7G8Q
ZNThM09lV6i5GsevTFNTEDSecx7iJjD8_jW94ug0-gYzLqFRneyN8vmnSUaHJKmbd4jEx1
_Vh9iH-eCdMtTo3UYjwYLt3fAQRrU9iRi4Z7wAbvWYOOf1bHtWR0VF9F1SrZ74gIgA5CFi
b1EXG3r3pMJwXNTV041tdZn3EhMUOlfElcBy5UhxiISoaB2COJNJKIEzc94OSJ42vg2_nd
wAzNiF8HXYQCklHqA0W_xxx6BCN3cIMQOHvv2PMf-33T5WqWtzQb6jPW0G919liomtw4Fm
Zn0nT9n8N9PfyibNuWww.eyJhbGciOiAiUlMyNTYifQ.eyJub25jZSI6ICJ1aF8wSllLTT
B3ZUlxRUlZTm96MGZ3IiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVy
IiwgInNkX2NsYWltcyI6IHsiZ2l2ZW5fbmFtZSI6ICJbXCJITlFHUTNoZTRJTnhDRGRRMU
VCWTlRXCIsIFwiSm9oblwiXSIsICJmYW1pbHlfbmFtZSI6ICJbXCJYYUtLX0JzYkptanZt
VjJ0bE1HSVBBXCIsIFwiRG9lXCJdIiwgImFkZHJlc3MiOiAiW1wia21fbjJzRVdwcTRkWn
o0Ry1Ualp6QVwiLCB7XCJzdHJlZXRfYWRkcmVzc1wiOiBcIjEyMyBNYWluIFN0XCIsIFwi
bG9jYWxpdHlcIjogXCJBbnl0b3duXCIsIFwicmVnaW9uXCI6IFwiQW55c3RhdGVcIiwgXC
Jjb3VudHJ5XCI6IFwiVVNcIn1dIn19.vQgoGfbQWXdZEKHlxk5UxezLX3B8Gjel4VENRLv
1JVp57nGEnQo84RHvEe9DVEcAqHRULpjnwwKh_slA06SIQbdAhJXRsdAZYVcpX-HNb-av-
obrNfFcDx2whcBCCiQIwqo-rnAkAE7wFlPmFdZ8bxsvzR4IPQVl9Ed5FTDSXCn7u3xC9Rq
DTFQPAbKONGwVHBVkZX6Osdig_mGNK_HGhE4USYrlc32N2iYq0P89hUQcNeK-r8jNU4NlY
S1mUkemkiU-94HqTEeQ3A_PJFheH7xsgg3N5rrPnXsPVePf5uI0AUtAhDfLa3NAQBDdeuE
d4GKvZxW5VA39a-DtUG3HaA
```

(Line breaks for presentation only.)

## SD-JWT Release Format

The following shows the contents of a release document for Example 1:

{#example-simple-release-payload}
```json
{
  "nonce": "uh_0JYKM0weIqEIYNoz0fw",
  "aud": "https://example.com/verifier",
  "sd_claims": {
    "given_name": "[\"HNQGQ3he4INxCDdQ1EBY9Q\", \"John\"]",
    "family_name": "[\"XaKK_BsbJmjvmV2tlMGIPA\", \"Doe\"]",
    "address": "[\"km_n2sEWpq4dZz4G-TjZzA\", {\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}]"
  }
}
```

For each claim, an array of the salt and the claim value is contained in the
`sd_claims` object. 

Again, the release document follows the same structure as the `sd_claims` in the SD-JWT. For Example 2, a release document limiting `address` to `region` and `country` only could look as follows:

{#example-simple_structured-release-payload}
```json
{
  "nonce": "3vuR2Spv4biwexqh8CAjWQ",
  "aud": "https://example.com/verifier",
  "sd_claims": {
    "given_name": "[\"7wPIFvwTg7rNCj8Jv2AXLQ\", \"John\"]",
    "family_name": "[\"jUDKEqq2KxVz3rMNP80d6w\", \"Doe\"]",
    "birthdate": "[\"7eSFThfsoMysrP4CvUlBnQ\", \"1940-01-01\"]",
    "address": {
      "region": "[\"9Z7AlXqp_RGYj7TsXhUZ3g\", \"Anystate\"]",
      "country": "[\"G5I-b8-ImhlbZBMIJKgTPg\", \"US\"]"
    }
  }
}
```

The SD-JWT Release MAY contain further claims, for example, to ensure a binding
to a concrete transaction (in the example the `nonce` and `aud` claims).

If holder binding is desired, the SD-JWT Release is signed by the holder. If no
holder binding is to be used, the `none` algorithm is used, i.e., the document
is not signed.

In any case, the result is encoded as described in [@!RFC7519] (here for Example 1):

{#example-simple-release-encoded}
```
eyJhbGciOiAiUlMyNTYifQ.eyJub25jZSI6ICJ1aF8wSllLTTB3ZUlxRUlZTm96MGZ3Iiw
gImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgInNkX2NsYWltcyI6I
HsiZ2l2ZW5fbmFtZSI6ICJbXCJITlFHUTNoZTRJTnhDRGRRMUVCWTlRXCIsIFwiSm9oblw
iXSIsICJmYW1pbHlfbmFtZSI6ICJbXCJYYUtLX0JzYkptanZtVjJ0bE1HSVBBXCIsIFwiR
G9lXCJdIiwgImFkZHJlc3MiOiAiW1wia21fbjJzRVdwcTRkWno0Ry1Ualp6QVwiLCB7XCJ
zdHJlZXRfYWRkcmVzc1wiOiBcIjEyMyBNYWluIFN0XCIsIFwibG9jYWxpdHlcIjogXCJBb
nl0b3duXCIsIFwicmVnaW9uXCI6IFwiQW55c3RhdGVcIiwgXCJjb3VudHJ5XCI6IFwiVVN
cIn1dIn19.vQgoGfbQWXdZEKHlxk5UxezLX3B8Gjel4VENRLv1JVp57nGEnQo84RHvEe9D
VEcAqHRULpjnwwKh_slA06SIQbdAhJXRsdAZYVcpX-HNb-av-obrNfFcDx2whcBCCiQIwq
o-rnAkAE7wFlPmFdZ8bxsvzR4IPQVl9Ed5FTDSXCn7u3xC9RqDTFQPAbKONGwVHBVkZX6O
sdig_mGNK_HGhE4USYrlc32N2iYq0P89hUQcNeK-r8jNU4NlYS1mUkemkiU-94HqTEeQ3A
_PJFheH7xsgg3N5rrPnXsPVePf5uI0AUtAhDfLa3NAQBDdeuEd4GKvZxW5VA39a-DtUG3H
aA
```

(Line breaks for presentation only.)
## Presentation Format

The SD-JWT and the SD-JWT Release can be combined into one document using `.` as a separator (here for Example 1):

{#example-simple-release-combined}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogIjFSWVJLQk5GZzFIX01vaUI4Y
m9BSTZSZ0VFMWlZT1VWVENTVF8ycm9lRHpUZjQwSUJOcmFHM2V5RF9OMmxhNkNnSzJRRnV
kMmR4alh1TmtLVzVIc1U2M0otc1I0NkExYzRoTUExTGNpal9SZllvOUpnVVFBV1NmbXhTQ
0llcGhJeXdpVk93VGd4UFJKeGJJU1RBd0QxNm05dWRHYkFoUDJ3TVZvTHhXd0FFUExjRUY
2TVp3VlowVzdFRDlOUktGVEpXZmY0TTQ4MVk4Njd0WkhtZmFWYWFjQmVwX0JBYzFkNFRPQ
lJRTEN0Rno1UFU5NHJZb1RBMy1ZdDd3bElOc1NtR2JPbmRRLW5ZZzBGWlJwM1ItTHppLWh
mUzk4WkxELTYtUHlxdTlZQ0gtOGV3dWd4R3hCcU5GVGVXQXF1QXEzbFZVSWNQMW90UDE0d
DZieFA5bDZ4dyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAic2RfY2xhaW1zIjogeyJzdWIiOiAiWkw0U1Q2akMxRU5rQmxBNnhVT
m92VEdoXzJqTzdHUkhmeGJ0QXpnNWsxTSIsICJnaXZlbl9uYW1lIjogIlZsemNfb1AzQnp
CM2psUUJJMlVfWEtDV01Ya2trdnFQbngtcTlRa1pZVWciLCAiZmFtaWx5X25hbWUiOiAiY
V92VjlkTDFNcDF2RGt6RFY5U0JBUlNsSVFtNGttM2Zkd2tVTE13VmRxNCIsICJlbWFpbCI
6ICJHQmQ3N1FxaHhaWW5La2pVSWhsNVpjVTF5TExmZk9faUxyZmVKTnZnNzJZIiwgInBob
25lX251bWJlciI6ICJrYVlKTnM3Zl9DRHhIY2wyOTVkMVF0OHdjdXVVUUtUTUZsbFgyTUd
WaE9vIiwgImFkZHJlc3MiOiAiVkstTEU5dmlVYUxwRVhwR2hnZXI0SkRMMEZIMmg2RUJWM
jZDcDYtQmR6YyIsICJiaXJ0aGRhdGUiOiAiUWozTTI0Wld1X3VGZGRnY2gweU10YzJoRXk
4dVFUREpueS1sVndkXzBKMCJ9fQ.T60iDKReljcIRl0Dkn_RtdbSF-014aKSq2F7Wn7G8Q
ZNThM09lV6i5GsevTFNTEDSecx7iJjD8_jW94ug0-gYzLqFRneyN8vmnSUaHJKmbd4jEx1
_Vh9iH-eCdMtTo3UYjwYLt3fAQRrU9iRi4Z7wAbvWYOOf1bHtWR0VF9F1SrZ74gIgA5CFi
b1EXG3r3pMJwXNTV041tdZn3EhMUOlfElcBy5UhxiISoaB2COJNJKIEzc94OSJ42vg2_nd
wAzNiF8HXYQCklHqA0W_xxx6BCN3cIMQOHvv2PMf-33T5WqWtzQb6jPW0G919liomtw4Fm
Zn0nT9n8N9PfyibNuWww.eyJhbGciOiAiUlMyNTYifQ.eyJub25jZSI6ICJ1aF8wSllLTT
B3ZUlxRUlZTm96MGZ3IiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVy
IiwgInNkX2NsYWltcyI6IHsiZ2l2ZW5fbmFtZSI6ICJbXCJITlFHUTNoZTRJTnhDRGRRMU
VCWTlRXCIsIFwiSm9oblwiXSIsICJmYW1pbHlfbmFtZSI6ICJbXCJYYUtLX0JzYkptanZt
VjJ0bE1HSVBBXCIsIFwiRG9lXCJdIiwgImFkZHJlc3MiOiAiW1wia21fbjJzRVdwcTRkWn
o0Ry1Ualp6QVwiLCB7XCJzdHJlZXRfYWRkcmVzc1wiOiBcIjEyMyBNYWluIFN0XCIsIFwi
bG9jYWxpdHlcIjogXCJBbnl0b3duXCIsIFwicmVnaW9uXCI6IFwiQW55c3RhdGVcIiwgXC
Jjb3VudHJ5XCI6IFwiVVNcIn1dIn19.vQgoGfbQWXdZEKHlxk5UxezLX3B8Gjel4VENRLv
1JVp57nGEnQo84RHvEe9DVEcAqHRULpjnwwKh_slA06SIQbdAhJXRsdAZYVcpX-HNb-av-
obrNfFcDx2whcBCCiQIwqo-rnAkAE7wFlPmFdZ8bxsvzR4IPQVl9Ed5FTDSXCn7u3xC9Rq
DTFQPAbKONGwVHBVkZX6Osdig_mGNK_HGhE4USYrlc32N2iYq0P89hUQcNeK-r8jNU4NlY
S1mUkemkiU-94HqTEeQ3A_PJFheH7xsgg3N5rrPnXsPVePf5uI0AUtAhDfLa3NAQBDdeuE
d4GKvZxW5VA39a-DtUG3HaA
```

(Line breaks for presentation only.)

# Verification

Verifiers MUST follow [@RFC8725] for checking the SD-JWT and, if signed, the
SD-JWT Release.

Verifiers MUST go through (at least) the following steps before
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
    2. For each claim in the SD-JWT Release:
       1. Ensure that the claim is present as well in `sd_claims` in the SD-JWT.
          If `sd_claims` is structured, the claim MUST be present at the same
          place within the structure.
       2. Check that the BASE64URL encoded hash of the claim value in the SD-JWT
          Release (which includes the salt and the actual claim value) matches
          the hash provided in the SD-JWT.
       3. Ensure that the claim value in the SD-JWT Release is a JSON-encoded
          array of exactly two values.
       4. Store the second of the two values. 
    3. Once all necessary claims have been verified, their values can be
       validated and used according to the requirements of the application. It
       MUST be ensured that all claims required for the application have been
       released.

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

## Example 3 - Complex Structured SD-JWT

In this example, a complex object such as those used for ekyc (todo reference) is used.

These claims are the payload of the SD-JWT:

{#example-complex_structured-sd-jwt-claims}
```json
{
  "verified_claims": {
    "verification": {
      "trust_framework": "de_aml",
      "time": "2012-04-23T18:25Z",
      "verification_process": "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
      "evidence": [
        {
          "type": "document",
          "method": "pipp",
          "time": "2012-04-22T11:30Z",
          "document": {
            "type": "idcard",
            "issuer": {
              "name": "Stadt Augsburg",
              "country": "DE"
            },
            "number": "53554554",
            "date_of_issuance": "2010-03-23",
            "date_of_expiry": "2020-03-22"
          }
        }
      ]
    },
    "claims": {
      "given_name": "Max",
      "family_name": "Meier",
      "birthdate": "1956-01-28",
      "place_of_birth": {
        "country": "DE",
        "locality": "Musterstadt"
      },
      "nationalities": [
        "DE"
      ],
      "address": {
        "locality": "Maxstadt",
        "postal_code": "12344",
        "country": "DE",
        "street_address": "An der Weide 22"
      }
    }
  },
  "birth_middle_name": "Timotheus",
  "salutation": "Dr.",
  "msisdn": "49123456789"
}
```

The following shows the resulting SD-JWT payload:

{#example-complex_structured-sd-jwt-payload}
```json
{
  "iss": "https://example.com/issuer",
  "sub_jwk": {
    "kty": "RSA",
    "n": "65ZaeNLzVUYCWd9qnKNvGArkhcX-WsRy5jq2e169njQPYf_vSk6bjUHlxnijUpN2zcYFqhfAICagNcFexgBKEAH5uY1CG4Hs-46w6ygPLoAHVlAhw_xiiFru_EEhaqmudH7hmigzQUU2RrpOavRhJayDg-eCDgA2ubwDliO3pZVJ99xnp-WI63PLJCLfgqO3-jBmAMjuCxbm9VxUeGAaNAV--9xZcqA4qJ39VMS9r8IXFG3ucybQ0ekA0rDLRlUTZXejvU_5WWK5FVlEAi6XOE3C1KJ5NwnGhknbop9FIMH304E7y4XlRwJ-6DGkw9dqlnra-YqcdouyBBuM11bBBQ",
    "e": "AQAB"
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "sd_claims": {
    "verified_claims": {
      "verification": {
        "trust_framework": "080wb-x4je493voZ7Y26GnlPMueqQdCAfFmU_B1gjQQ",
        "time": "eRIFnhrIjJj8wmXpLcl2VbnEMR77W3_D8d_04c36YUQ",
        "verification_process": "cM_0au_VsNzJ_9MuGKmWmpH53wu90p9BPzsqdLOPlJY",
        "evidence": [
          {
            "type": "FsNAPAgwPLWoJ0FbEriBq_ROwJ_cr-o-NYySR-Tqym8",
            "method": "JDCkRKQOeaCxnsripuJr4EHA-4xqf1y206wn6kxbQnU",
            "time": "oE3GhurLRaYKHbRYLaVWozrx6uXT3bwLlaOfAOMFCPc",
            "document": {
              "type": "VJlOPl63Ha2qvVFnK-_bw_jaFHp989nix__oj3smtpE",
              "issuer": {
                "name": "JJkj4G7bmYWkCn0Rl8ciaL79q2wEzSBv0RoMbXECktw",
                "country": "53tzRgQzjpIvKHZskLfGV8sxxElgEc1nBfkAhbwAnUs"
              },
              "number": "mXrmsLOSQJ592iIwXzR72MKcaS0PcL49cP-uOwx-hFk",
              "date_of_issuance": "LA-7h2i1H0-zfcFc5bPppHULqFctfJtACPqr657q3Z4",
              "date_of_expiry": "TP9rzRMIQ-oI7YF-NFnKOmdGqLKzStyYCrFwDDPTUk4"
            }
          }
        ]
      },
      "claims": {
        "given_name": "6A4F9ToI99W-WPA20Qs8G-940_ckTSRmzqpSIfRKRhE",
        "family_name": "g8BLXJtTvvp2gcb_IGmbdNyqLwg6t8EkD6cCEIvxI_0",
        "birthdate": "NUX1SbFkIQTOUTh0ejVpFnxXU3P9eQ6EVkGu0WngYuM",
        "place_of_birth": {
          "country": "bKBd-AZEZC_5U1iNIFG8jqpuRZFCqIGib3SptmaDznE",
          "locality": "GUYA14aPrNgSi-URhCnTLcju_xlLhHvrsx4mqjVkN0g"
        },
        "nationalities": "makkO4VMpbs8b1Ql4C9_p-ipMVke98xDWku3bfbYCL0",
        "address": "eOm6di-Um1CeIyoyrDJjeFESPk5FW5N3kx2cJFRdZgE"
      }
    },
    "birth_middle_name": "73iFLSpqDhAhrXpUyWf5tFIXGjHlJvFWR3xIgJmFQiM",
    "salutation": "-yH6JpSrlYIJJuelz_8dQizfn5Sawhk9fgTMEpugAAY",
    "msisdn": "vKXRBansg8QfCY3ZCTfhnXKj2TtWNEupR8OhiAiqsuE"
  }
}
```

The SD-JWT is then signed by the issuer to create a document like the following:

{#example-complex_structured-sd-jwt-encoded}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogIjY1WmFlTkx6VlVZQ1dkOXFuS
052R0Fya2hjWC1Xc1J5NWpxMmUxNjlualFQWWZfdlNrNmJqVUhseG5palVwTjJ6Y1lGcWh
mQUlDYWdOY0ZleGdCS0VBSDV1WTFDRzRIcy00Nnc2eWdQTG9BSFZsQWh3X3hpaUZydV9FR
WhhcW11ZEg3aG1pZ3pRVVUyUnJwT2F2UmhKYXlEZy1lQ0RnQTJ1YndEbGlPM3BaVko5OXh
ucC1XSTYzUExKQ0xmZ3FPMy1qQm1BTWp1Q3hibTlWeFVlR0FhTkFWLS05eFpjcUE0cUozO
VZNUzlyOElYRkczdWN5YlEwZWtBMHJETFJsVVRaWGVqdlVfNVdXSzVGVmxFQWk2WE9FM0M
xS0o1TnduR2hrbmJvcDlGSU1IMzA0RTd5NFhsUndKLTZER2t3OWRxbG5yYS1ZcWNkb3V5Q
kJ1TTExYkJCUSIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAic2RfY2xhaW1zIjogeyJ2ZXJpZmllZF9jbGFpbXMiOiB7InZlcmlma
WNhdGlvbiI6IHsidHJ1c3RfZnJhbWV3b3JrIjogIjA4MHdiLXg0amU0OTN2b1o3WTI2R25
sUE11ZXFRZENBZkZtVV9CMWdqUVEiLCAidGltZSI6ICJlUklGbmhySWpKajh3bVhwTGNsM
lZibkVNUjc3VzNfRDhkXzA0YzM2WVVRIiwgInZlcmlmaWNhdGlvbl9wcm9jZXNzIjogImN
NXzBhdV9Wc056Sl85TXVHS21XbXBINTN3dTkwcDlCUHpzcWRMT1BsSlkiLCAiZXZpZGVuY
2UiOiBbeyJ0eXBlIjogIkZzTkFQQWd3UExXb0owRmJFcmlCcV9ST3dKX2NyLW8tTll5U1I
tVHF5bTgiLCAibWV0aG9kIjogIkpEQ2tSS1FPZWFDeG5zcmlwdUpyNEVIQS00eHFmMXkyM
DZ3bjZreGJRblUiLCAidGltZSI6ICJvRTNHaHVyTFJhWUtIYlJZTGFWV296cng2dVhUM2J
3TGxhT2ZBT01GQ1BjIiwgImRvY3VtZW50IjogeyJ0eXBlIjogIlZKbE9QbDYzSGEycXZWR
m5LLV9id19qYUZIcDk4OW5peF9fb2ozc210cEUiLCAiaXNzdWVyIjogeyJuYW1lIjogIkp
Ka2o0RzdibVlXa0NuMFJsOGNpYUw3OXEyd0V6U0J2MFJvTWJYRUNrdHciLCAiY291bnRye
SI6ICI1M3R6UmdRempwSXZLSFpza0xmR1Y4c3h4RWxnRWMxbkJma0FoYndBblVzIn0sICJ
udW1iZXIiOiAibVhybXNMT1NRSjU5MmlJd1h6UjcyTUtjYVMwUGNMNDljUC11T3d4LWhGa
yIsICJkYXRlX29mX2lzc3VhbmNlIjogIkxBLTdoMmkxSDAtemZjRmM1YlBwcEhVTHFGY3R
mSnRBQ1BxcjY1N3EzWjQiLCAiZGF0ZV9vZl9leHBpcnkiOiAiVFA5cnpSTUlRLW9JN1lGL
U5GbktPbWRHcUxLelN0eVlDckZ3RERQVFVrNCJ9fV19LCAiY2xhaW1zIjogeyJnaXZlbl9
uYW1lIjogIjZBNEY5VG9JOTlXLVdQQTIwUXM4Ry05NDBfY2tUU1JtenFwU0lmUktSaEUiL
CAiZmFtaWx5X25hbWUiOiAiZzhCTFhKdFR2dnAyZ2NiX0lHbWJkTnlxTHdnNnQ4RWtENmN
DRUl2eElfMCIsICJiaXJ0aGRhdGUiOiAiTlVYMVNiRmtJUVRPVVRoMGVqVnBGbnhYVTNQO
WVRNkVWa0d1MFduZ1l1TSIsICJwbGFjZV9vZl9iaXJ0aCI6IHsiY291bnRyeSI6ICJiS0J
kLUFaRVpDXzVVMWlOSUZHOGpxcHVSWkZDcUlHaWIzU3B0bWFEem5FIiwgImxvY2FsaXR5I
jogIkdVWUExNGFQck5nU2ktVVJoQ25UTGNqdV94bExoSHZyc3g0bXFqVmtOMGcifSwgIm5
hdGlvbmFsaXRpZXMiOiAibWFra080Vk1wYnM4YjFRbDRDOV9wLWlwTVZrZTk4eERXa3UzY
mZiWUNMMCIsICJhZGRyZXNzIjogImVPbTZkaS1VbTFDZUl5b3lyREpqZUZFU1BrNUZXNU4
za3gyY0pGUmRaZ0UifX0sICJiaXJ0aF9taWRkbGVfbmFtZSI6ICI3M2lGTFNwcURoQWhyW
HBVeVdmNXRGSVhHakhsSnZGV1IzeElnSm1GUWlNIiwgInNhbHV0YXRpb24iOiAiLXlINkp
wU3JsWUlKSnVlbHpfOGRRaXpmbjVTYXdoazlmZ1RNRXB1Z0FBWSIsICJtc2lzZG4iOiAid
ktYUkJhbnNnOFFmQ1kzWkNUZmhuWEtqMlR0V05FdXBSOE9oaUFpcXN1RSJ9fQ.gYjufqOp
enverw8SwlamK04YamHu74z1F0Onvz3LFlLLHXnWGfXFCbK8NXoNC29eB-LzM2fthDSs1q
zUUXBi6AqngbR1jzMuFH8HawKwsAGRCCxSEdTSix9L3gNVCXeVBT_SgTDDZEgyyIRYYv7q
b5owVJ4vm5PTjuRor7BgQNlfv1VIFSIrDokJjncFrkh9gqlswFBWeanSMbF_MysiFPqzjY
fpHoPqH9Xhj4MbQ58Ae8Id5cQvGBT7clnEpl5hXsobmeW6MehvSyOaQKsSAB3YHmOijfuK
IfNhYiEWfk12JVaR2k4qwcI2Qb9xOUGQknE-mWYOztFCm3QW7heZsw.ewogICAgInNkX2N
sYWltcyI6IHsKICAgICAgICAidmVyaWZpZWRfY2xhaW1zIjogewogICAgICAgICAgICAid
mVyaWZpY2F0aW9uIjogewogICAgICAgICAgICAgICAgInRydXN0X2ZyYW1ld29yayI6ICJ
bXCJ3cnVIWmF3SXJrXzBqYWM2WFhJTE1RXCIsIFwiZGVfYW1sXCJdIiwKICAgICAgICAgI
CAgICAgICJ0aW1lIjogIltcIkx4YzRCWTJyckN6QXpOV1JPTTl2M0FcIiwgXCIyMDEyLTA
0LTIzVDE4OjI1WlwiXSIsCiAgICAgICAgICAgICAgICAidmVyaWZpY2F0aW9uX3Byb2Nlc
3MiOiAiW1widXlrNklhelluS1VRQ2I4aGN3Nkx1Z1wiLCBcImYyNGM2Zi02ZDNmLTRlYzU
tOTczZS1iMGQ4NTA2ZjNiYzdcIl0iLAogICAgICAgICAgICAgICAgImV2aWRlbmNlIjogW
wogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgInR5cGU
iOiAiW1wiV3k4MjlPNHY1bFlFbEppNXd4QThFd1wiLCBcImRvY3VtZW50XCJdIiwKICAgI
CAgICAgICAgICAgICAgICAgICAgIm1ldGhvZCI6ICJbXCJ0WEMyMzd2M1NrWTNoUnFYaW9
aN3R3XCIsIFwicGlwcFwiXSIsCiAgICAgICAgICAgICAgICAgICAgICAgICJ0aW1lIjogI
ltcImI0d1FzczM2VHBEcjRWazB0RHdONmdcIiwgXCIyMDEyLTA0LTIyVDExOjMwWlwiXSI
sCiAgICAgICAgICAgICAgICAgICAgICAgICJkb2N1bWVudCI6IHsKICAgICAgICAgICAgI
CAgICAgICAgICAgICAgICJ0eXBlIjogIltcIm52czVWMjhiUHI1T2NkMVpMdHprUndcIiw
gXCJpZGNhcmRcIl0iLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgImlzc3VlciI6I
HsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAibmFtZSI6ICJbXCJxZTMxQ1Y
3VVBPU2JlanNuT3lIOTFRXCIsIFwiU3RhZHQgQXVnc2J1cmdcIl0iLAogICAgICAgICAgI
CAgICAgICAgICAgICAgICAgICAgICJjb3VudHJ5IjogIltcIkd1ZnFEMzRuTWpqSFFGRG4
5MGk3RXdcIiwgXCJERVwiXSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0sCiAgI
CAgICAgICAgICAgICAgICAgICAgICAgICAibnVtYmVyIjogIltcIjR1QUhOWEl3TEFlNGd
kWXk1a0JqUlFcIiwgXCI1MzU1NDU1NFwiXSIsCiAgICAgICAgICAgICAgICAgICAgICAgI
CAgICAiZGF0ZV9vZl9pc3N1YW5jZSI6ICJbXCI4UnYyQzhRRUdKR1FCcVgwWE8xdjhnXCI
sIFwiMjAxMC0wMy0yM1wiXSIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAiZGF0Z
V9vZl9leHBpcnkiOiAiW1wiTjItcEg0WGpMdVRreER3SnZPQ05TUVwiLCBcIjIwMjAtMDM
tMjJcIl0iCiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgI
CB9CiAgICAgICAgICAgICAgICBdCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgICJjbGF
pbXMiOiB7CiAgICAgICAgICAgICAgICAiZ2l2ZW5fbmFtZSI6ICJbXCJqZ2hEQ2dsTFYxV
0NCdkxFOERjMUVRXCIsIFwiTWF4XCJdIiwKICAgICAgICAgICAgICAgICJmYW1pbHlfbmF
tZSI6ICJbXCJBRHNkS1dzby0taWpNNnFQTmttOUJ3XCIsIFwiTWVpZXJcIl0iLAogICAgI
CAgICAgICAgICAgImJpcnRoZGF0ZSI6ICJbXCJ6TE9nUGVJUVVmUDl3NlFHcjZvc2xnXCI
sIFwiMTk1Ni0wMS0yOFwiXSIsCiAgICAgICAgICAgICAgICAicGxhY2Vfb2ZfYmlydGgiO
iB7CiAgICAgICAgICAgICAgICAgICAgImNvdW50cnkiOiAiW1wic19YdkdVaWNfUm1wUjF
mZVNqNjRrZ1wiLCBcIkRFXCJdIiwKICAgICAgICAgICAgICAgICAgICAibG9jYWxpdHkiO
iAiW1wiYjZiNUgwUk1mYmRJeGloaFNGSnQ2QVwiLCBcIk11c3RlcnN0YWR0XCJdIgogICA
gICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgICJuYXRpb25hbGl0aWVzIjogIltcI
klsb3hfVUZFS0tIN09uMlh1bENxa3dcIiwgW1wiREVcIl1dIiwKICAgICAgICAgICAgICA
gICJhZGRyZXNzIjogIltcIlcyNnVCa2ZkTE9MNHNSWllHYzFMZGdcIiwge1wibG9jYWxpd
HlcIjogXCJNYXhzdGFkdFwiLCBcInBvc3RhbF9jb2RlXCI6IFwiMTIzNDRcIiwgXCJjb3V
udHJ5XCI6IFwiREVcIiwgXCJzdHJlZXRfYWRkcmVzc1wiOiBcIkFuIGRlciBXZWlkZSAyM
lwifV0iCiAgICAgICAgICAgIH0KICAgICAgICB9LAogICAgICAgICJiaXJ0aF9taWRkbGV
fbmFtZSI6ICJbXCJOSC1jaWF1NWdtYklXNGk3T0JQUi1RXCIsIFwiVGltb3RoZXVzXCJdI
iwKICAgICAgICAic2FsdXRhdGlvbiI6ICJbXCI4Yk1uN3ZKWm93aVVfY09vdDdfRndBXCI
sIFwiRHIuXCJdIiwKICAgICAgICAibXNpc2RuIjogIltcIl9FSzE3SjBULURvYjhDeUVCU
kozcVFcIiwgXCI0OTEyMzQ1Njc4OVwiXSIKICAgIH0KfQ
```

(Line breaks for presentation only.)

A release document for some of the claims:

{#example-complex_structured-release-payload}
```json
{
  "nonce": "E2lXXUtqsMUNAwBIZ-eP-A",
  "aud": "https://example.com/verifier",
  "sd_claims": {
    "verified_claims": {
      "verification": {
        "trust_framework": "[\"wruHZawIrk_0jac6XXILMQ\", \"de_aml\"]",
        "time": "[\"Lxc4BY2rrCzAzNWROM9v3A\", \"2012-04-23T18:25Z\"]",
        "evidence": [
          {
            "type": "[\"Wy829O4v5lYElJi5wxA8Ew\", \"document\"]"
          }
        ]
      },
      "claims": {
        "given_name": "[\"jghDCglLV1WCBvLE8Dc1EQ\", \"Max\"]",
        "family_name": "[\"ADsdKWso--ijM6qPNkm9Bw\", \"Meier\"]",
        "birthdate": "[\"zLOgPeIQUfP9w6QGr6oslg\", \"1956-01-28\"]",
        "place_of_birth": {
          "country": "[\"s_XvGUic_RmpR1feSj64kg\", \"DE\"]"
        }
      }
    }
  }
}
```

# Document History

   [[ To be removed from the final specification ]]

   -00

   *  Renamed to SD-JWT (focus on JWT instead of JWS since signature is optional)
   *  Make holder binding optional
   *  Rename proof to release, since when there is no signature, the term "proof" can be misleading
   *  Improved the structure of the description
   *  Described verification steps
   *  All examples generated from python demo implementation
   *  Examples for structured objects


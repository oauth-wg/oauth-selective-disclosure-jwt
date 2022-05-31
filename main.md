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

Note that claim names are used as keys in a key-value pair, where the value is the hash.
Claim names are not hashed because SD-JWT already reveals information about the issuer and the schema,
and revealing the claim names does not provide any additional information.

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
    "n": "tX2xcWvjAkLl5uN5gaTDeDVFpevOcNjjPM-ryCWKjbUoh5nyDEaFpqvv3WDeGwWeBjMXed4htovR-3fJyW5S0d_tUWcdEmSGeqrcUnb8C71VU_pCQYD6MH9YjRCmt3RjnuFeHZiJymbgT8h7cVL0ivTX7qL9ftMCN5JRoNYF5DMGBXlvCgLCGIbdK7-tkPyhdeGgsFJa_aM4ft5SRSsqzrP76vyv55VxPMmDoGJrAJn38HlkqoIEXhjjMh0EACuC8HXM9XwovtOqeXAO4GgJwKEwWgypa5QwqReHoQIcUYqYTJCwikrzkhvtIlqIdkSRKUSX-A9gjtQ_E-gyt93NGQ",
    "e": "AQAB"
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "_sd": {
    "sub": "LbnhkOr5oS7KjeUrxezAu8TG0CpWz0jSixy6tffuo04",
    "given_name": "fUMdn88aaoyKTHrvZd6AuLmPraGhPJ0zF5r_JhxCVZs",
    "family_name": "9h5vgv6TpFV6GmnPtugiMLl5tHetHeb5X_2cKHjN7cw",
    "email": "fPZ92dtYMCN2Nb-2ac_zSH19p4yakUXrZl_-wSgaazA",
    "phone_number": "QdSffzNzzd0n60MsSmuiKj6Y6Enk2b-BS-KtEePde5M",
    "address": "JFu99NUXPq55f6DFBZ22rMkxMNHayCrfPG0FDsqbyDs",
    "birthdate": "Ia1Tc6_Xnt5CJc2LtKcu6Wvqr42glBGGcjGOye8Zf3U"
  }
}
```

The SD-JWT is then signed by the issuer to create a document like the following:

{#example-simple-sd-jwt-encoded}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInRYMnhjV3ZqQWtMbDV1TjVnY
VREZURWRnBldk9jTmpqUE0tcnlDV0tqYlVvaDVueURFYUZwcXZ2M1dEZUd3V2VCak1YZWQ
0aHRvdlItM2ZKeVc1UzBkX3RVV2NkRW1TR2VxcmNVbmI4QzcxVlVfcENRWUQ2TUg5WWpSQ
210M1JqbnVGZUhaaUp5bWJnVDhoN2NWTDBpdlRYN3FMOWZ0TUNONUpSb05ZRjVETUdCWGx
2Q2dMQ0dJYmRLNy10a1B5aGRlR2dzRkphX2FNNGZ0NVNSU3NxenJQNzZ2eXY1NVZ4UE1tR
G9HSnJBSm4zOEhsa3FvSUVYaGpqTWgwRUFDdUM4SFhNOVh3b3Z0T3FlWEFPNEdnSndLRXd
XZ3lwYTVRd3FSZUhvUUljVVlxWVRKQ3dpa3J6a2h2dElscUlka1NSS1VTWC1BOWdqdFFfR
S1neXQ5M05HUSIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAiX3NkIjogeyJzdWIiOiAiTGJuaGtPcjVvUzdLamVVcnhlekF1OFRHM
ENwV3owalNpeHk2dGZmdW8wNCIsICJnaXZlbl9uYW1lIjogImZVTWRuODhhYW95S1RIcnZ
aZDZBdUxtUHJhR2hQSjB6RjVyX0poeENWWnMiLCAiZmFtaWx5X25hbWUiOiAiOWg1dmd2N
lRwRlY2R21uUHR1Z2lNTGw1dEhldEhlYjVYXzJjS0hqTjdjdyIsICJlbWFpbCI6ICJmUFo
5MmR0WU1DTjJOYi0yYWNfelNIMTlwNHlha1VYclpsXy13U2dhYXpBIiwgInBob25lX251b
WJlciI6ICJRZFNmZnpOenpkMG42ME1zU211aUtqNlk2RW5rMmItQlMtS3RFZVBkZTVNIiw
gImFkZHJlc3MiOiAiSkZ1OTlOVVhQcTU1ZjZERkJaMjJyTWt4TU5IYXlDcmZQRzBGRHNxY
nlEcyIsICJiaXJ0aGRhdGUiOiAiSWExVGM2X1hudDVDSmMyTHRLY3U2V3ZxcjQyZ2xCR0d
jakdPeWU4WmYzVSJ9fQ.IS4oc1f3XuxhNSnecIXbpT-3ZVwgbjpMSfpyqhFUEE2T_ij3uW
Bqb1_zn0nLvIvXDs8rn6l10ilHwCgpMaPmYAE8_nfZtNwvfAFnwBFjzdrJOJWhZ5dp6UJe
VULOZvjsCw1EpyRbBgIyZ9QiLzRJ_5JS1C1AelDDyXxI3FZYYc3-1MqQMnaXR7AWOct698
t-LsookAA_LxXx-RYKG1wygEp9e9BzgCxQugsdGejMPTZyfaQewGrJalQm8bYvSXKcJ1DG
-T297kFEV_VTaeLCOoan1DS1DtaH48Q13yUUmdwil8jqjpVgf_lU0A7dO4AYmojgvdng-c
MLWSp5YtL_Gw.ewogICAgIl9zZCI6IHsKICAgICAgICAic3ViIjogIltcImVsdVY1T2czZ
1NOSUk4RVluc3hBX0FcIiwgXCI2YzVjMGE0OS1iNTg5LTQzMWQtYmFlNy0yMTkxMjJhOWV
jMmNcIl0iLAogICAgICAgICJnaXZlbl9uYW1lIjogIltcIjZJajd0TS1hNWlWUEdib1M1d
G12VkFcIiwgXCJKb2huXCJdIiwKICAgICAgICAiZmFtaWx5X25hbWUiOiAiW1wiZUk4Wld
tOVFuS1BwTlBlTmVuSGRoUVwiLCBcIkRvZVwiXSIsCiAgICAgICAgImVtYWlsIjogIltcI
lFnX082NHpxQXhlNDEyYTEwOGlyb0FcIiwgXCJqb2huZG9lQGV4YW1wbGUuY29tXCJdIiw
KICAgICAgICAicGhvbmVfbnVtYmVyIjogIltcIkFKeC0wOTVWUHJwVHRONFFNT3FST0FcI
iwgXCIrMS0yMDItNTU1LTAxMDFcIl0iLAogICAgICAgICJhZGRyZXNzIjogIltcIlBjMzN
KTTJMY2hjVV9sSGdndl91ZlFcIiwge1wic3RyZWV0X2FkZHJlc3NcIjogXCIxMjMgTWFpb
iBTdFwiLCBcImxvY2FsaXR5XCI6IFwiQW55dG93blwiLCBcInJlZ2lvblwiOiBcIkFueXN
0YXRlXCIsIFwiY291bnRyeVwiOiBcIlVTXCJ9XSIsCiAgICAgICAgImJpcnRoZGF0ZSI6I
CJbXCJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBXCIsIFwiMTk0MC0wMS0wMVwiXSIKICAgIH0
KfQ
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
    "n": "vxqABmnBwkDVrTK99gD70GFSXfVsTZdcX_CCjYWU6wE6AuPTFDSiFtP4tdIo_BY4fnO7E_-JbyBv-xeot79ZiF-4yKD9jPs0n79205quVdO_GKWAZD0fQTyxFTm7qaBelPtuHahiyiz1Q0W5HJPFiFOqAQAd7le7ZO3y-3gFrWATwD6FNYE_dLhna7Kd6aNyIN9lFUrKdJh__jOEv1hLbdojL8bnX5LKcYltJ6hfW6vQHuUs2cghvwqGaGWy8fn1ilWhDF8uED-FkruyfaXoCFhFL8MQcZx1Sim_Tpmg18hoQXnFazhZUTnCtlWFTBQKyjbZ0S6GqS8hYChE-taZ5Q",
    "e": "AQAB"
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "_sd": {
    "sub": "LbnhkOr5oS7KjeUrxezAu8TG0CpWz0jSixy6tffuo04",
    "given_name": "fUMdn88aaoyKTHrvZd6AuLmPraGhPJ0zF5r_JhxCVZs",
    "family_name": "9h5vgv6TpFV6GmnPtugiMLl5tHetHeb5X_2cKHjN7cw",
    "email": "fPZ92dtYMCN2Nb-2ac_zSH19p4yakUXrZl_-wSgaazA",
    "phone_number": "QdSffzNzzd0n60MsSmuiKj6Y6Enk2b-BS-KtEePde5M",
    "address": {
      "street_address": "4FpVpd563Owh9G3HkGNTN9FiSHT0e6y9-Abk_IuG86M",
      "locality": "Kr0BpdZz6yU8HMhjyYHh1EEgJxeUyLIpJEi47iXhp8Y",
      "region": "QXxWKvcV4Bc9t3M7MF43W5vdCnWtA9hsYX8ycWLu1LQ",
      "country": "3itkoMzrDrinn7T0MUbAmrMm1ya1LzbBgif_50WoFOs"
    },
    "birthdate": "fvLCnDm3r4VSYcBF3pIlXP4ulEoHuHOfG_YmFZEuxpQ"
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
  "_sd": {
    "sub": "[\"eluV5Og3gSNII8EYnsxA_A\", \"6c5c0a49-b589-431d-bae7-219122a9ec2c\"]",
    "given_name": "[\"6Ij7tM-a5iVPGboS5tmvVA\", \"John\"]",
    "family_name": "[\"eI8ZWm9QnKPpNPeNenHdhQ\", \"Doe\"]",
    "email": "[\"Qg_O64zqAxe412a108iroA\", \"johndoe@example.com\"]",
    "phone_number": "[\"AJx-095VPrpTtN4QMOqROA\", \"+1-202-555-0101\"]",
    "address": "[\"Pc33JM2LchcU_lHggv_ufQ\", {\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}]",
    "birthdate": "[\"G02NSrQfjFXQ7Io09syajA\", \"1940-01-01\"]"
  }
}
```

### Example 2 - SVC for a Structured SD-JWT

The SVC for Example 2 is as follows:

{#example-simple_structured-svc-payload}
```json
{
  "_sd": {
    "sub": "[\"eluV5Og3gSNII8EYnsxA_A\", \"6c5c0a49-b589-431d-bae7-219122a9ec2c\"]",
    "given_name": "[\"6Ij7tM-a5iVPGboS5tmvVA\", \"John\"]",
    "family_name": "[\"eI8ZWm9QnKPpNPeNenHdhQ\", \"Doe\"]",
    "email": "[\"Qg_O64zqAxe412a108iroA\", \"johndoe@example.com\"]",
    "phone_number": "[\"AJx-095VPrpTtN4QMOqROA\", \"+1-202-555-0101\"]",
    "address": {
      "street_address": "[\"Pc33JM2LchcU_lHggv_ufQ\", \"123 Main St\"]",
      "locality": "[\"G02NSrQfjFXQ7Io09syajA\", \"Anytown\"]",
      "region": "[\"lklxF5jMYlGTPUovMNIvCA\", \"Anystate\"]",
      "country": "[\"nPuoQnkRFq3BIeAm7AnXFA\", \"US\"]"
    },
    "birthdate": "[\"5bPs1IquZNa0hkaFzzzZNw\", \"1940-01-01\"]"
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
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInRYMnhjV3ZqQWtMbDV1TjVnY
VREZURWRnBldk9jTmpqUE0tcnlDV0tqYlVvaDVueURFYUZwcXZ2M1dEZUd3V2VCak1YZWQ
0aHRvdlItM2ZKeVc1UzBkX3RVV2NkRW1TR2VxcmNVbmI4QzcxVlVfcENRWUQ2TUg5WWpSQ
210M1JqbnVGZUhaaUp5bWJnVDhoN2NWTDBpdlRYN3FMOWZ0TUNONUpSb05ZRjVETUdCWGx
2Q2dMQ0dJYmRLNy10a1B5aGRlR2dzRkphX2FNNGZ0NVNSU3NxenJQNzZ2eXY1NVZ4UE1tR
G9HSnJBSm4zOEhsa3FvSUVYaGpqTWgwRUFDdUM4SFhNOVh3b3Z0T3FlWEFPNEdnSndLRXd
XZ3lwYTVRd3FSZUhvUUljVVlxWVRKQ3dpa3J6a2h2dElscUlka1NSS1VTWC1BOWdqdFFfR
S1neXQ5M05HUSIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAiX3NkIjogeyJzdWIiOiAiTGJuaGtPcjVvUzdLamVVcnhlekF1OFRHM
ENwV3owalNpeHk2dGZmdW8wNCIsICJnaXZlbl9uYW1lIjogImZVTWRuODhhYW95S1RIcnZ
aZDZBdUxtUHJhR2hQSjB6RjVyX0poeENWWnMiLCAiZmFtaWx5X25hbWUiOiAiOWg1dmd2N
lRwRlY2R21uUHR1Z2lNTGw1dEhldEhlYjVYXzJjS0hqTjdjdyIsICJlbWFpbCI6ICJmUFo
5MmR0WU1DTjJOYi0yYWNfelNIMTlwNHlha1VYclpsXy13U2dhYXpBIiwgInBob25lX251b
WJlciI6ICJRZFNmZnpOenpkMG42ME1zU211aUtqNlk2RW5rMmItQlMtS3RFZVBkZTVNIiw
gImFkZHJlc3MiOiAiSkZ1OTlOVVhQcTU1ZjZERkJaMjJyTWt4TU5IYXlDcmZQRzBGRHNxY
nlEcyIsICJiaXJ0aGRhdGUiOiAiSWExVGM2X1hudDVDSmMyTHRLY3U2V3ZxcjQyZ2xCR0d
jakdPeWU4WmYzVSJ9fQ.IS4oc1f3XuxhNSnecIXbpT-3ZVwgbjpMSfpyqhFUEE2T_ij3uW
Bqb1_zn0nLvIvXDs8rn6l10ilHwCgpMaPmYAE8_nfZtNwvfAFnwBFjzdrJOJWhZ5dp6UJe
VULOZvjsCw1EpyRbBgIyZ9QiLzRJ_5JS1C1AelDDyXxI3FZYYc3-1MqQMnaXR7AWOct698
t-LsookAA_LxXx-RYKG1wygEp9e9BzgCxQugsdGejMPTZyfaQewGrJalQm8bYvSXKcJ1DG
-T297kFEV_VTaeLCOoan1DS1DtaH48Q13yUUmdwil8jqjpVgf_lU0A7dO4AYmojgvdng-c
MLWSp5YtL_Gw.eyJhbGciOiAiUlMyNTYifQ.eyJub25jZSI6ICIyR0xDNDJzS1F2ZUNmR2
ZyeU5STjl3IiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgIl9z
ZCI6IHsiZ2l2ZW5fbmFtZSI6ICJbXCI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBXCIsIFwiSm
9oblwiXSIsICJmYW1pbHlfbmFtZSI6ICJbXCJlSThaV205UW5LUHBOUGVOZW5IZGhRXCIs
IFwiRG9lXCJdIiwgImFkZHJlc3MiOiAiW1wiUGMzM0pNMkxjaGNVX2xIZ2d2X3VmUVwiLC
B7XCJzdHJlZXRfYWRkcmVzc1wiOiBcIjEyMyBNYWluIFN0XCIsIFwibG9jYWxpdHlcIjog
XCJBbnl0b3duXCIsIFwicmVnaW9uXCI6IFwiQW55c3RhdGVcIiwgXCJjb3VudHJ5XCI6IF
wiVVNcIn1dIn19.Z6l-sUfifRth6djDqvHng4Zm1TNkKGiQqC5P_5Nn0pSo5dMaClpheNc
NAPiPSf39A0jB8HBFceUQ_dmfTxi1U4NGFxbp-gTB00rPCY_RzCR3J-jgGmilYGLt4g2D6
BV1YuLmFLBgT_IW6GR5mq_RJYK6AANYrVbVPmBbMTfrYT9SAsDkKKWXWz4i0gScLhmz4yi
7FoNsvGtgb7WMtlHN86eJDtuayGHr8aCr95EAaUnuMbcT_WzGc_ifhzDBLJ4U0MVNlfiyk
9Fd8OgnwC11cE3QE3kKDUeQcNAAo81K_sCt-_AwvhMzSj1OK81L4frekUkfomzrCGbdVSC
bXLCfEg
```

(Line breaks for presentation only.)

## SD-JWT Release Format

The following shows the contents of a release document for Example 1:

{#example-simple-release-payload}
```json
{
  "nonce": "2GLC42sKQveCfGfryNRN9w",
  "aud": "https://example.com/verifier",
  "_sd": {
    "given_name": "[\"6Ij7tM-a5iVPGboS5tmvVA\", \"John\"]",
    "family_name": "[\"eI8ZWm9QnKPpNPeNenHdhQ\", \"Doe\"]",
    "address": "[\"Pc33JM2LchcU_lHggv_ufQ\", {\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}]"
  }
}
```

For each claim, an array of the salt and the claim value is contained in the
`sd_claims` object. 

Again, the release document follows the same structure as the `sd_claims` in the SD-JWT. For Example 2, a release document limiting `address` to `region` and `country` only could look as follows:

{#example-simple_structured-release-payload}
```json
{
  "nonce": "2GLC42sKQveCfGfryNRN9w",
  "aud": "https://example.com/verifier",
  "_sd": {
    "given_name": "[\"6Ij7tM-a5iVPGboS5tmvVA\", \"John\"]",
    "family_name": "[\"eI8ZWm9QnKPpNPeNenHdhQ\", \"Doe\"]",
    "birthdate": "[\"5bPs1IquZNa0hkaFzzzZNw\", \"1940-01-01\"]",
    "address": {
      "region": "[\"lklxF5jMYlGTPUovMNIvCA\", \"Anystate\"]",
      "country": "[\"nPuoQnkRFq3BIeAm7AnXFA\", \"US\"]"
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
eyJhbGciOiAiUlMyNTYifQ.eyJub25jZSI6ICIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3Iiw
gImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgIl9zZCI6IHsiZ2l2Z
W5fbmFtZSI6ICJbXCI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBXCIsIFwiSm9oblwiXSIsICJ
mYW1pbHlfbmFtZSI6ICJbXCJlSThaV205UW5LUHBOUGVOZW5IZGhRXCIsIFwiRG9lXCJdI
iwgImFkZHJlc3MiOiAiW1wiUGMzM0pNMkxjaGNVX2xIZ2d2X3VmUVwiLCB7XCJzdHJlZXR
fYWRkcmVzc1wiOiBcIjEyMyBNYWluIFN0XCIsIFwibG9jYWxpdHlcIjogXCJBbnl0b3duX
CIsIFwicmVnaW9uXCI6IFwiQW55c3RhdGVcIiwgXCJjb3VudHJ5XCI6IFwiVVNcIn1dIn1
9.Z6l-sUfifRth6djDqvHng4Zm1TNkKGiQqC5P_5Nn0pSo5dMaClpheNcNAPiPSf39A0jB
8HBFceUQ_dmfTxi1U4NGFxbp-gTB00rPCY_RzCR3J-jgGmilYGLt4g2D6BV1YuLmFLBgT_
IW6GR5mq_RJYK6AANYrVbVPmBbMTfrYT9SAsDkKKWXWz4i0gScLhmz4yi7FoNsvGtgb7WM
tlHN86eJDtuayGHr8aCr95EAaUnuMbcT_WzGc_ifhzDBLJ4U0MVNlfiyk9Fd8OgnwC11cE
3QE3kKDUeQcNAAo81K_sCt-_AwvhMzSj1OK81L4frekUkfomzrCGbdVSCbXLCfEg
```

(Line breaks for presentation only.)
## Presentation Format

The SD-JWT and the SD-JWT Release can be combined into one document using `.` as a separator (here for Example 1):

{#example-simple-release-combined}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInRYMnhjV3ZqQWtMbDV1TjVnY
VREZURWRnBldk9jTmpqUE0tcnlDV0tqYlVvaDVueURFYUZwcXZ2M1dEZUd3V2VCak1YZWQ
0aHRvdlItM2ZKeVc1UzBkX3RVV2NkRW1TR2VxcmNVbmI4QzcxVlVfcENRWUQ2TUg5WWpSQ
210M1JqbnVGZUhaaUp5bWJnVDhoN2NWTDBpdlRYN3FMOWZ0TUNONUpSb05ZRjVETUdCWGx
2Q2dMQ0dJYmRLNy10a1B5aGRlR2dzRkphX2FNNGZ0NVNSU3NxenJQNzZ2eXY1NVZ4UE1tR
G9HSnJBSm4zOEhsa3FvSUVYaGpqTWgwRUFDdUM4SFhNOVh3b3Z0T3FlWEFPNEdnSndLRXd
XZ3lwYTVRd3FSZUhvUUljVVlxWVRKQ3dpa3J6a2h2dElscUlka1NSS1VTWC1BOWdqdFFfR
S1neXQ5M05HUSIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAiX3NkIjogeyJzdWIiOiAiTGJuaGtPcjVvUzdLamVVcnhlekF1OFRHM
ENwV3owalNpeHk2dGZmdW8wNCIsICJnaXZlbl9uYW1lIjogImZVTWRuODhhYW95S1RIcnZ
aZDZBdUxtUHJhR2hQSjB6RjVyX0poeENWWnMiLCAiZmFtaWx5X25hbWUiOiAiOWg1dmd2N
lRwRlY2R21uUHR1Z2lNTGw1dEhldEhlYjVYXzJjS0hqTjdjdyIsICJlbWFpbCI6ICJmUFo
5MmR0WU1DTjJOYi0yYWNfelNIMTlwNHlha1VYclpsXy13U2dhYXpBIiwgInBob25lX251b
WJlciI6ICJRZFNmZnpOenpkMG42ME1zU211aUtqNlk2RW5rMmItQlMtS3RFZVBkZTVNIiw
gImFkZHJlc3MiOiAiSkZ1OTlOVVhQcTU1ZjZERkJaMjJyTWt4TU5IYXlDcmZQRzBGRHNxY
nlEcyIsICJiaXJ0aGRhdGUiOiAiSWExVGM2X1hudDVDSmMyTHRLY3U2V3ZxcjQyZ2xCR0d
jakdPeWU4WmYzVSJ9fQ.IS4oc1f3XuxhNSnecIXbpT-3ZVwgbjpMSfpyqhFUEE2T_ij3uW
Bqb1_zn0nLvIvXDs8rn6l10ilHwCgpMaPmYAE8_nfZtNwvfAFnwBFjzdrJOJWhZ5dp6UJe
VULOZvjsCw1EpyRbBgIyZ9QiLzRJ_5JS1C1AelDDyXxI3FZYYc3-1MqQMnaXR7AWOct698
t-LsookAA_LxXx-RYKG1wygEp9e9BzgCxQugsdGejMPTZyfaQewGrJalQm8bYvSXKcJ1DG
-T297kFEV_VTaeLCOoan1DS1DtaH48Q13yUUmdwil8jqjpVgf_lU0A7dO4AYmojgvdng-c
MLWSp5YtL_Gw.eyJhbGciOiAiUlMyNTYifQ.eyJub25jZSI6ICIyR0xDNDJzS1F2ZUNmR2
ZyeU5STjl3IiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgIl9z
ZCI6IHsiZ2l2ZW5fbmFtZSI6ICJbXCI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBXCIsIFwiSm
9oblwiXSIsICJmYW1pbHlfbmFtZSI6ICJbXCJlSThaV205UW5LUHBOUGVOZW5IZGhRXCIs
IFwiRG9lXCJdIiwgImFkZHJlc3MiOiAiW1wiUGMzM0pNMkxjaGNVX2xIZ2d2X3VmUVwiLC
B7XCJzdHJlZXRfYWRkcmVzc1wiOiBcIjEyMyBNYWluIFN0XCIsIFwibG9jYWxpdHlcIjog
XCJBbnl0b3duXCIsIFwicmVnaW9uXCI6IFwiQW55c3RhdGVcIiwgXCJjb3VudHJ5XCI6IF
wiVVNcIn1dIn19.Z6l-sUfifRth6djDqvHng4Zm1TNkKGiQqC5P_5Nn0pSo5dMaClpheNc
NAPiPSf39A0jB8HBFceUQ_dmfTxi1U4NGFxbp-gTB00rPCY_RzCR3J-jgGmilYGLt4g2D6
BV1YuLmFLBgT_IW6GR5mq_RJYK6AANYrVbVPmBbMTfrYT9SAsDkKKWXWz4i0gScLhmz4yi
7FoNsvGtgb7WMtlHN86eJDtuayGHr8aCr95EAaUnuMbcT_WzGc_ifhzDBLJ4U0MVNlfiyk
9Fd8OgnwC11cE3QE3kKDUeQcNAAo81K_sCt-_AwvhMzSj1OK81L4frekUkfomzrCGbdVSC
bXLCfEg
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
    "n": "0pyGviWMy34jiHS6a9wGP5uuHO2Y7CRwbaJ0GwmsXb7BJv1ZBzB06NruBfXFs7P_e9Imsr-SfH_IgYxw5RBJCQzdztgwHxIgH86R-Cm_q9K3k0SqYH7jDYvvVELqvU5V0l1Ve9qu9Z3mT2gy9zyH0cbLK_wOoEy4KIMnyR6Oy88cgU769MXmDe2tqUqRozfXYEvZ4jaDsbWBC5I7p8R9nYXqZYSK5SXEqUxDDH-h6VyiY1m7CWFuNZ09bk2A5xCTXjZVQYANjhkBr4m9urunuUsCjQEEv0kFnPBFbG8y5-76PWwIjs1okBK7-LR5rGihXZydIXsNBwo0RrQqZFetsw",
    "e": "AQAB"
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "_sd": {
    "verified_claims": {
      "verification": {
        "trust_framework": "UI-SRNlQFy-YEFE46yyHKqc64jmM65q8ma9cq2V_erY",
        "time": "jI-FYlteydXzsjRIrXBZs9foBSNF1Od1Q-4XnuqpgjI",
        "verification_process": "F979I7b5ZhADtyYMlYxctdc9-IalD_Td0HpfcFBzVXs",
        "evidence": [
          {
            "type": "i2w3mrKAQV2nhTa5c2koZ-aQTBDoSaVfvYk7aLQianc",
            "method": "fEQ0tVPD67GfO30h_SRs8ZPbnZ_vwEt5S8lUOR77va0",
            "time": "9jueDP5r0gTB64DqdCZbek3yaS5AJJnW8FEkWtPTaOk",
            "document": {
              "type": "K-rZQk89w89YBhjUNUho07suLxhG8Sl2JTPAcoAJB34",
              "issuer": {
                "name": "BkCULCU-txVGvzNqnWe5DxefFvJE8LMib8GV3I3WO90",
                "country": "DSyF5TtmYgLk92u4GkDQzSdFbvIbw5rkFjzSsJJsyw4"
              },
              "number": "epH3OuU51TBelOE4PX6ueHwr1ZtoUjzG-7pZjIAsXg8",
              "date_of_issuance": "cVvqTueVq6OWz-dJj2cdo19A0Ajj859eGDzDfwPYyN4",
              "date_of_expiry": "nxJBNdtwvb2TKKJNGvF6_1ywEdKrotj66C88WPomLfo"
            }
          }
        ]
      },
      "claims": {
        "given_name": "y9uFPHAVqNAZ7PJyk1-1yQJZZWZzKGP5FLt9txKM84M",
        "family_name": "XyUikY8V8MWeBfXUOp8gI7F7-yC28Jr5IyDgvBxXzd4",
        "birthdate": "7GlieMLJhM78C_uQQp9wUXSZLeqBN1YGQT87BIubyKU",
        "place_of_birth": {
          "country": "RN3xcnLYX_GDhVwfPvtisuLPfi0d74zqihFbQrd_UG0",
          "locality": "iNkpWqJ9kIZQq95dzSyEZjbPJs6Fqu7GFBKouEC3OxE"
        },
        "nationalities": "-tinYGK0GXnkfARxiNIWq0VnzNRl-Kv3KY3m5g5Femg",
        "address": "63EzPV0yvTpeOgV34yCwweCvO-2wxts2Wqbja_SuwPQ"
      }
    },
    "birth_middle_name": "vM68I6XnrVlyt1LxK9xxgFycsjtw2vLdGpNgk3E8QQ4",
    "salutation": "iThfCu2ulLoe5i6gCEq--Y6R-gxHHtIukXb9qnfjH5k",
    "msisdn": "xUpU-azBYdXeJidc8Yw5MXtfPz4_4kArJhflXcxzkzs"
  }
}
```

The SD-JWT is then signed by the issuer to create a document like the following:

{#example-complex_structured-sd-jwt-encoded}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogIjBweUd2aVdNeTM0amlIUzZhO
XdHUDV1dUhPMlk3Q1J3YmFKMEd3bXNYYjdCSnYxWkJ6QjA2TnJ1QmZYRnM3UF9lOUltc3I
tU2ZIX0lnWXh3NVJCSkNRemR6dGd3SHhJZ0g4NlItQ21fcTlLM2swU3FZSDdqRFl2dlZFT
HF2VTVWMGwxVmU5cXU5WjNtVDJneTl6eUgwY2JMS193T29FeTRLSU1ueVI2T3k4OGNnVTc
2OU1YbURlMnRxVXFSb3pmWFlFdlo0amFEc2JXQkM1STdwOFI5bllYcVpZU0s1U1hFcVV4R
ERILWg2VnlpWTFtN0NXRnVOWjA5YmsyQTV4Q1RYalpWUVlBTmpoa0JyNG05dXJ1bnVVc0N
qUUVFdjBrRm5QQkZiRzh5NS03NlBXd0lqczFva0JLNy1MUjVyR2loWFp5ZElYc05Cd28wU
nJRcVpGZXRzdyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAiX3NkIjogeyJ2ZXJpZmllZF9jbGFpbXMiOiB7InZlcmlmaWNhdGlvb
iI6IHsidHJ1c3RfZnJhbWV3b3JrIjogIlVJLVNSTmxRRnktWUVGRTQ2eXlIS3FjNjRqbU0
2NXE4bWE5Y3EyVl9lclkiLCAidGltZSI6ICJqSS1GWWx0ZXlkWHpzalJJclhCWnM5Zm9CU
05GMU9kMVEtNFhudXFwZ2pJIiwgInZlcmlmaWNhdGlvbl9wcm9jZXNzIjogIkY5NzlJN2I
1WmhBRHR5WU1sWXhjdGRjOS1JYWxEX1RkMEhwZmNGQnpWWHMiLCAiZXZpZGVuY2UiOiBbe
yJ0eXBlIjogImkydzNtcktBUVYybmhUYTVjMmtvWi1hUVRCRG9TYVZmdllrN2FMUWlhbmM
iLCAibWV0aG9kIjogImZFUTB0VlBENjdHZk8zMGhfU1JzOFpQYm5aX3Z3RXQ1UzhsVU9SN
zd2YTAiLCAidGltZSI6ICI5anVlRFA1cjBnVEI2NERxZENaYmVrM3lhUzVBSkpuVzhGRWt
XdFBUYU9rIiwgImRvY3VtZW50IjogeyJ0eXBlIjogIkstclpRazg5dzg5WUJoalVOVWhvM
DdzdUx4aEc4U2wySlRQQWNvQUpCMzQiLCAiaXNzdWVyIjogeyJuYW1lIjogIkJrQ1VMQ1U
tdHhWR3Z6TnFuV2U1RHhlZkZ2SkU4TE1pYjhHVjNJM1dPOTAiLCAiY291bnRyeSI6ICJEU
3lGNVR0bVlnTGs5MnU0R2tEUXpTZEZidklidzVya0ZqelNzSkpzeXc0In0sICJudW1iZXI
iOiAiZXBIM091VTUxVEJlbE9FNFBYNnVlSHdyMVp0b1VqekctN3BaaklBc1hnOCIsICJkY
XRlX29mX2lzc3VhbmNlIjogImNWdnFUdWVWcTZPV3otZEpqMmNkbzE5QTBBamo4NTllR0R
6RGZ3UFl5TjQiLCAiZGF0ZV9vZl9leHBpcnkiOiAibnhKQk5kdHd2YjJUS0tKTkd2RjZfM
Xl3RWRLcm90ajY2Qzg4V1BvbUxmbyJ9fV19LCAiY2xhaW1zIjogeyJnaXZlbl9uYW1lIjo
gInk5dUZQSEFWcU5BWjdQSnlrMS0xeVFKWlpXWnpLR1A1Rkx0OXR4S004NE0iLCAiZmFta
Wx5X25hbWUiOiAiWHlVaWtZOFY4TVdlQmZYVU9wOGdJN0Y3LXlDMjhKcjVJeURndkJ4WHp
kNCIsICJiaXJ0aGRhdGUiOiAiN0dsaWVNTEpoTTc4Q191UVFwOXdVWFNaTGVxQk4xWUdRV
Dg3Qkl1YnlLVSIsICJwbGFjZV9vZl9iaXJ0aCI6IHsiY291bnRyeSI6ICJSTjN4Y25MWVh
fR0RoVndmUHZ0aXN1TFBmaTBkNzR6cWloRmJRcmRfVUcwIiwgImxvY2FsaXR5IjogImlOa
3BXcUo5a0laUXE5NWR6U3lFWmpiUEpzNkZxdTdHRkJLb3VFQzNPeEUifSwgIm5hdGlvbmF
saXRpZXMiOiAiLXRpbllHSzBHWG5rZkFSeGlOSVdxMFZuek5SbC1LdjNLWTNtNWc1RmVtZ
yIsICJhZGRyZXNzIjogIjYzRXpQVjB5dlRwZU9nVjM0eUN3d2VDdk8tMnd4dHMyV3FiamF
fU3V3UFEifX0sICJiaXJ0aF9taWRkbGVfbmFtZSI6ICJ2TTY4STZYbnJWbHl0MUx4Szl4e
GdGeWNzanR3MnZMZEdwTmdrM0U4UVE0IiwgInNhbHV0YXRpb24iOiAiaVRoZkN1MnVsTG9
lNWk2Z0NFcS0tWTZSLWd4SEh0SXVrWGI5cW5makg1ayIsICJtc2lzZG4iOiAieFVwVS1he
kJZZFhlSmlkYzhZdzVNWHRmUHo0XzRrQXJKaGZsWGN4emt6cyJ9fQ.f6w58KAyROyRM6Kd
lyweJCL5uIOJGDTIFaOP0gSEaPMqSliXdAs3XAmZWTZNwZQDNTyDGJwXlI0VusbLfzzaUU
2NBq1YGCi8o4p91vgqizJa7GD7nl1-BiAEm1bDl5SOoh_Zm3DlmHUncruNECLsV8t7VfNL
Zod1SgJ9Ia1F_B6vPovcAxVtRa1cQUkpiQsjwdkYA5MM-SCvOSR7aNM71HHScvZ6hapLpa
ZSXXGt0s-rjhYX-3fI7ZCRK_n0ElIXev2Lv7qd8xYCpcaYUgkzi1gQ1PRv7DT4_VnWsjk7
XwnRgwwPfXkkEdBLIhB3TDWtxGT5ZPBgoffgxHKxXyn3dQ.ewogICAgIl9zZCI6IHsKICA
gICAgICAidmVyaWZpZWRfY2xhaW1zIjogewogICAgICAgICAgICAidmVyaWZpY2F0aW9uI
jogewogICAgICAgICAgICAgICAgInRydXN0X2ZyYW1ld29yayI6ICJbXCJlbHVWNU9nM2d
TTklJOEVZbnN4QV9BXCIsIFwiZGVfYW1sXCJdIiwKICAgICAgICAgICAgICAgICJ0aW1lI
jogIltcIjZJajd0TS1hNWlWUEdib1M1dG12VkFcIiwgXCIyMDEyLTA0LTIzVDE4OjI1Wlw
iXSIsCiAgICAgICAgICAgICAgICAidmVyaWZpY2F0aW9uX3Byb2Nlc3MiOiAiW1wiZUk4W
ldtOVFuS1BwTlBlTmVuSGRoUVwiLCBcImYyNGM2Zi02ZDNmLTRlYzUtOTczZS1iMGQ4NTA
2ZjNiYzdcIl0iLAogICAgICAgICAgICAgICAgImV2aWRlbmNlIjogWwogICAgICAgICAgI
CAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgInR5cGUiOiAiW1wiUWdfTzY
0enFBeGU0MTJhMTA4aXJvQVwiLCBcImRvY3VtZW50XCJdIiwKICAgICAgICAgICAgICAgI
CAgICAgICAgIm1ldGhvZCI6ICJbXCJBSngtMDk1VlBycFR0TjRRTU9xUk9BXCIsIFwicGl
wcFwiXSIsCiAgICAgICAgICAgICAgICAgICAgICAgICJ0aW1lIjogIltcIlBjMzNKTTJMY
2hjVV9sSGdndl91ZlFcIiwgXCIyMDEyLTA0LTIyVDExOjMwWlwiXSIsCiAgICAgICAgICA
gICAgICAgICAgICAgICJkb2N1bWVudCI6IHsKICAgICAgICAgICAgICAgICAgICAgICAgI
CAgICJ0eXBlIjogIltcIkcwMk5TclFmakZYUTdJbzA5c3lhakFcIiwgXCJpZGNhcmRcIl0
iLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgImlzc3VlciI6IHsKICAgICAgICAgI
CAgICAgICAgICAgICAgICAgICAgICAibmFtZSI6ICJbXCJsa2x4RjVqTVlsR1RQVW92TU5
JdkNBXCIsIFwiU3RhZHQgQXVnc2J1cmdcIl0iLAogICAgICAgICAgICAgICAgICAgICAgI
CAgICAgICAgICJjb3VudHJ5IjogIltcIm5QdW9RbmtSRnEzQkllQW03QW5YRkFcIiwgXCJ
ERVwiXSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgI
CAgICAgICAgICAgICAibnVtYmVyIjogIltcIjViUHMxSXF1Wk5hMGhrYUZ6enpaTndcIiw
gXCI1MzU1NDU1NFwiXSIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAiZGF0ZV9vZ
l9pc3N1YW5jZSI6ICJbXCI1YTJXMF9OcmxFWnpmcW1rXzdQcS13XCIsIFwiMjAxMC0wMy0
yM1wiXSIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAiZGF0ZV9vZl9leHBpcnkiO
iAiW1wieTFzVlU1d2RmSmFoVmRnd1BnUzdSUVwiLCBcIjIwMjAtMDMtMjJcIl0iCiAgICA
gICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgI
CAgICAgICBdCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgICJjbGFpbXMiOiB7CiAgICA
gICAgICAgICAgICAiZ2l2ZW5fbmFtZSI6ICJbXCJIYlE0WDhzclZXM1FEeG5JSmRxeU9BX
CIsIFwiTWF4XCJdIiwKICAgICAgICAgICAgICAgICJmYW1pbHlfbmFtZSI6ICJbXCJDOUd
Tb3VqdmlKcXVFZ1lmb2pDYjFBXCIsIFwiTWVpZXJcIl0iLAogICAgICAgICAgICAgICAgI
mJpcnRoZGF0ZSI6ICJbXCJreDVrRjE3Vi14MEptd1V4OXZndnR3XCIsIFwiMTk1Ni0wMS0
yOFwiXSIsCiAgICAgICAgICAgICAgICAicGxhY2Vfb2ZfYmlydGgiOiB7CiAgICAgICAgI
CAgICAgICAgICAgImNvdW50cnkiOiAiW1wiSDNvMXVzd1A3NjBGaTJ5ZUdkVkNFUVwiLCB
cIkRFXCJdIiwKICAgICAgICAgICAgICAgICAgICAibG9jYWxpdHkiOiAiW1wiT0JLbFRWb
HZMZy1BZHdxWUdiUDhaQVwiLCBcIk11c3RlcnN0YWR0XCJdIgogICAgICAgICAgICAgICA
gfSwKICAgICAgICAgICAgICAgICJuYXRpb25hbGl0aWVzIjogIltcIk0wSmI1N3Q0MXVic
mtTdXlyRFQzeEFcIiwgW1wiREVcIl1dIiwKICAgICAgICAgICAgICAgICJhZGRyZXNzIjo
gIltcIkRzbXRLTmdwVjRkQUhwanJjYW9zQXdcIiwge1wibG9jYWxpdHlcIjogXCJNYXhzd
GFkdFwiLCBcInBvc3RhbF9jb2RlXCI6IFwiMTIzNDRcIiwgXCJjb3VudHJ5XCI6IFwiREV
cIiwgXCJzdHJlZXRfYWRkcmVzc1wiOiBcIkFuIGRlciBXZWlkZSAyMlwifV0iCiAgICAgI
CAgICAgIH0KICAgICAgICB9LAogICAgICAgICJiaXJ0aF9taWRkbGVfbmFtZSI6ICJbXCJ
lSzVvNXBIZmd1cFBwbHRqMXFoQUp3XCIsIFwiVGltb3RoZXVzXCJdIiwKICAgICAgICAic
2FsdXRhdGlvbiI6ICJbXCJqN0FEZGIwVVZiMExpMGNpUGNQMGV3XCIsIFwiRHIuXCJdIiw
KICAgICAgICAibXNpc2RuIjogIltcIldweEpyRnVYOHVTaTJwNGh0MDlqdndcIiwgXCI0O
TEyMzQ1Njc4OVwiXSIKICAgIH0KfQ
```

(Line breaks for presentation only.)

A release document for some of the claims:

{#example-complex_structured-release-payload}
```json
{
  "nonce": "2GLC42sKQveCfGfryNRN9w",
  "aud": "https://example.com/verifier",
  "_sd": {
    "verified_claims": {
      "verification": {
        "trust_framework": "[\"eluV5Og3gSNII8EYnsxA_A\", \"de_aml\"]",
        "time": "[\"6Ij7tM-a5iVPGboS5tmvVA\", \"2012-04-23T18:25Z\"]",
        "evidence": [
          {
            "type": "[\"Qg_O64zqAxe412a108iroA\", \"document\"]"
          }
        ]
      },
      "claims": {
        "given_name": "[\"HbQ4X8srVW3QDxnIJdqyOA\", \"Max\"]",
        "family_name": "[\"C9GSoujviJquEgYfojCb1A\", \"Meier\"]",
        "birthdate": "[\"kx5kF17V-x0JmwUx9vgvtw\", \"1956-01-28\"]",
        "place_of_birth": {
          "country": "[\"H3o1uswP760Fi2yeGdVCEQ\", \"DE\"]"
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
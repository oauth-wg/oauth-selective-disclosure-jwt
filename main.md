%%%
title = "Selective Disclosure JWT (SD-JWT)"
abbrev = "SD-JWT"
ipr = "trust200902"
area = "Security"
workgroup = "Web Authorization Protocol"
keyword = ["security", "oauth2"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-fett-oauth-selective-disclosure-jwt-00"
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
documents that support selective disclosure of JWT claim values. 

{mainmatter}

# Introduction {#Introduction}

The JSON-based claims in a signed JSON Web Token (JWT) [@!RFC7519] document
are secured against modification using JSON Web Signature (JWS) [@!RFC7515] digital signatures.
A consumer of a signed JWT document that has checked the document's signature can safely assume
that the contents of the document have not been modified.  However, anyone
receiving an unencrypted JWT can read all of the claims and likewise,
anyone with the decryption key receiving an encrypted JWT
can also read all of the claims.

This document describes a format for a signed JWT that support selective
disclosure (SD-JWT), enabling sharing only a subset of the claims included in 
the original signed JWT instead of releasing all the claims to every verifier. 
During issuance, an SD-JWT is sent from the issuer to the holder alongside an SD-JWT Salt/Value Container (SVC),
a JSON object that contains the mapping between raw claim values contained in the SD-JWT 
and the salts for each claim value. 

This document also defines a format for SD-JWT Releases (SD-JWT-R),
which conveys a subset of the claim values of an SD-JWT that the holder 
is selectively releasing to the verifier. During presentation, SD-JWT-R and SD-JWT are both sent
to the verifier from the holder. To verify claim values received in SD-JWT-R, 
verifier uses salts in SD-JWT-R to compute the hashes of the claim values and compare them to the hashes in SD-JWT.

One of the common use cases of a signed JWT is representing a user's identity created by an issuer.
In such a use case, there has been no privacy-related concerns with existing JOSE signature schemes,
because when a signed JWT is one-time use, it contains only JWT claims that the user has consented
in real time to release to the verifier. However, when a signed JWT is intended to be multi-use, 
the ability to selectively disclose a subset of the claims depending on the verifier becomes crucial
to ensure minimum disclosure and prevent verifier from obtaining claims irrelevant for the transaction at hand.

One example of such a multi-use JWT is a verifiable credential, or a
tamper-evident credential with a cryptographically verifiable authorship that
contains claims about a subject. SD-JWTs defined in this document enable such
selective disclosure of claims. 

While JWTs for claims describing natural persons are a common use case, the
mechanisms defined in this document can be used for many other use cases as
well.

Note: so far agreed to define holder binding (user's public key contained inside an SD-JWT) as an option.
It is not mandatory since holder binding is use case specific and orthogonal to the general mechanism of 
selective disclosure defined here.


## Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they
appear in all capitals, as shown here.

**base64url** denotes the URL-safe base64 encoding without padding defined in
Section 2 of [@!RFC7515].

# Terms and Definitions

## Selective Disclosure JWT (SD-JWT) 
   A JWT [@!RFC7515] created by the issuer, which is signed as a JWS [@!RFC7515], 
   that supports selective disclosure as defined in this document.

## SD-JWT Salt/Value Container (SVC) 
   A JSON object created by the issuer that contains mapping between 
   raw claim values contained in the SD-JWT and the salts for each claim value.

## SD-JWT Release (SD-JWT-R) 
   A JWT created by the holder that contains a subset of the claim values of an SD-JWT in a verifiable way. 

## Holder binding 
   Ability of the holder to prove legitimate possession of SD-JWT by proving 
   control over the same private key during the issuance and presentation. SD-JWT signed by the issuer contains
   a public key or a reference to a public key that matches to the private key controlled by the holder.

## Issuer 
   An entity that creates SD-JWTs (2.1).

## Holder 
   An entity that received SD-JWTs (2.1) from the issuer and has control over them.

## Verifier 
   An entity that requests, checks and extracts the claims from SSD-JWT-R (2.2)

Note: discuss if we want to include Client, Authorization Server for the purpose of
ensuring continuity and separating the entity from the actor.

# Flow Diagram

~~~ ascii-art
+------+                                                                     +----------+
|        |                         +--------+                                |          |
|        |                         |        |                                |          |
| Issuer |--Issues SD-JWT and SVC->| Holder |--Presents SD-JWT-R and SD-JWT->| Verifier |
|        |                         |        |                                |          |
|        |                         +--------+                                |          |
+--------+                                                                   +----------+
~~~
Figure: SD-JWT Issuance and Presentation Flow

# Concepts

In the following section, the concepts of SD-JWTs and SD-JWT Releases are described at a
conceptual level.

## Creating an SD-JWT

An SD-JWT, at its core, is a digitally signed document containing hashes over the claim values with unique salts,
optionally the holder's public key or a reference thereto and other metadata. 
It MUST be digitally signed using the issuer's private key.

```
SD-JWT-DOC = (METADATA, HOLDER-PUBLIC-KEY?, HS-CLAIMS)
SD-JWT = SD-JWT-DOC | SIG(SD-JWT-DOC, ISSUER-PRIV-KEY)
```

`HS-CLAIMS` is usually a simple object with claim names mapped to hashes over the claim values with unique salts:
```
HS-CLAIMS = (
    CLAIM-NAME: HASH(SALT | CLAIM-VALUE)
)*
```

`HS-CLAIMS` can also be nested deeper to capture more complex objects, as will be shown later.

The SD-JWT is sent from the issuer to the holder, together with the mapping of the plain-text claim values, the salt values, and potentially some other information. 

## Creating an SD-JWT Release

To disclose to a verifier a subset of the SD-JWT claim values, a holder creates a JWT such as the
following:

```
RELEASE-DOC = (METADATA, SALTS)
RELEASE = RELEASE-DOC | SIG(RELEASE-DOC, HOLDER-PRIV-KEY)?
```

Note that the signature over `RELEASE-DOC` is optional and required only if holder binding is desired.

`SALTS` is usually a simple object with claim names mapped to values and salts:

```
SALTS = (
    CLAIM-NAME: (DISCLOSED-SALT, DISCLOSED-VALUE)
)
```

Just as `HS-CLAIMS`, `SALTS` can be more complex as well.

The SD-JWT-R is sent together with the SD-JWT from the holder to the
verifier.

## Verifying an SD-JWT Release

A verifier checks that 

 * if holder binding is desired, the `RELEASE` was signed by
 the private key belonging to the public key contained in `SD-JWT-DOC`.
 * for each claim in `RELEASE`, the hash `HASH(DISCLOSED-SALT | DISCLOSED-VALUE)` 
 matches the hash under the given claim name in the SD-JWT.

The detailed algorithm is described below.

# Data Formats

This section defines a data format for SD-JWTs (containing hashes of the salted claim values) 
and for SD-JWT Salt/Value Containers (containing the mapping of the plain-text claim values 
and the salt values).

## Format of an SD-JWT

An SD-JWT is a JWT that MUST be signed using the issuer's private key.

### SD-JWT Claims

The payload of an SD-JWT can consist of the following claims.

#### `_sd` (Selectively Disclosable) Claim

An SD-JWT MUST include hashes of the salted claim values that are included by the issuer
under the property `_sd`. 

The issuer MUST choose a unique salt value for each claim value. Each salt value
MUST contain at least 128 bits of pseudorandom data, making it hard for an
attacker to guess. The salt value MUST then be encoded as a string. It is
RECOMMENDED to base64url-encode at least 16 pseudorandom bytes.

The issuer MUST build the hashes by hashing over a string that is formed by
JSON-encoding an ordered array containing the salt and the claim value, e.g.:
`["6qMQvRL5haj","Peter"]`. The hash value is then base64url-encoded. Note that
the precise JSON encoding can vary, and therefore, the JSON encodings MUST be
sent to the holder along with the SD-JWT, as described below. 

#### Hash Function

* `hash_alg`: REQUIRED. Hash algorithm used by the Issuer to generate hashes 
of the salted claim values. Hash algorithm identifier MUST be a value
from the "Hash Name String" column in the IANA "Named Information
Hash Algorithm" registry [IANA.Hash.Algorithms]. SD-JWTs
with hash algorithm identifiers not found in this registry are not
considered valid and applications will need to detect and handle this
error, should it occur.

#### Holder Public Key Claim

If the issuer wants to enable holder binding, it MAY include a public key
associated with the holder, or a reference thereto. 

It is out of the scope of this document to describe how the holder key pair is
established. For example, the holder MAY provide a key pair to the issuer, 
the issuer MAY create the key pair for the holder, or
holder and issuer MAY use pre-established key material.

Note: need to define how holder public key is included, right now examples are using `sub_jwk` I think.

#### Other Claims

The payload of SD-JWT MAY contain other JWT claims, such as `iss`, `iat`, etc.
as defined by the applications using SD-JWTs.

### Flat and Structured `_sd` objects

The `_sd` object can be a 'flat' object, directly containing all claim names and
hashed claim values without any deeper structure. The `_sd` object can also be a
'structured' object, where some claims and their respective hashes are contained
in places deeper in the structure. it is at the issuer's discretion whether to use
a 'flat' or 'structured' `_sd` SD-JWT object, and how to structure it such that
it is suitable for the use case.

Examples 1 is a non-normative example of an SD-JWT using a 'flat' `_sd` object
and example 2 is a non-normative example of an SD-JWT using a 'structured' `_sd` object.
The difference between the examples is how an `address` claim is disclosed.

Both examples use a following object as a set of claims that the Issuer is issuing:

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

Appendix 1 shows a more complex example using claims from eKYC (todo:
reference).

### Example 1 - Flat SD-JWT

The following is a non-normative example of the payload of an SD-JWT. The issuer 
is using a flat structure, i.e. all of the claims the `address` claim can only be disclosed in full.

{#example-simple-sd-jwt-payload}
```json
{
  "iss": "https://example.com/issuer",
  "sub_jwk": {
    "kty": "RSA",
    "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x65659kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjtth8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mTz10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wqf_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSGuxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw",
    "e": "AQAB"
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "_sd": {
    "sub": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.JWB5eNSupjFnFghM2W0LgJGfoEU1U2H5TZUdN7BQolEAuX5y8Ttggw.2l1TmIXIm__1suit7ZWCkw.NYQ6SdbO9zSv7IdfW60BD-HkF0eS3OSWLoU3_fWOw3d8p81TLDX_iZj3sEjDrNZR.hVIyLIjOEMgwu4OxvkAZcw",
    "given_name": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.3-PyIrJ9jMWaRGZ4zoIDF5TDWtFk7fqQWsQEeuDYm3Bex7Iy9lqgag.M5z2nz8K055VrDENfZfknw.JKw5sZQNliftEh6bUo9cnw.jmukSCofCNOf5x6C68r7jg",
    "family_name": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.c1SYCxW8Ni51zLSMaaLuaGi2xwYhk8qeYzSKJt6zyTitxhF7NDKb1g.vftUzOgItBL84q52LHrhdQ.kNOOM-ISk1d4gLJXe2blgg.uDiwT74zaAjfxPa4NR_mNQ",
    "email": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.AEcT1COKUpbAVJEGaa8RBrqp9WypS1fV9UJRTSsZdn04cJj2FZB-ng.lJop1XNH3cIkih6lJiJD0A.qyhH7wDwb2XuKEIn_aPBF2eU90iJDdFtpY3H7JFo1PA.NMJr6T8y-f64JUvcHcHU9w",
    "phone_number": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.iMltvX1SYFOAF9sv1v38p6MjSVE7FEndvXOB5vkEIkTFZ5t7ktd4Bg.E2247n1hNSnc-mW_JJnt9g.RaAEGFFg8uL8PEMe0APIuEsalXc9HtuLAy5jRJnesSo.n8P8kU75ExUbPIKT3hNJqg",
    "address": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.WP1v5eON3wHk8WIvSxWCOsbXXMCQQp2AIyfltkIzQYmat-NmYtRQqA.iEdo7DxQ4mCGORBSIpGqUA.pdY8xhJW_Li1-3zwJUC6GuiOGi89hEy81JmwwyZ_rPjCRLPgR_6Cf_z0WoN6IeS0o5R1jYg2g-ZR3-IWnfgAtfMi2pZlivoHP-wO1tBZ0KTQlQu58dBBJg9WYRR2ojK9.u8am5a3WiuIlUg5d1M1Chg",
    "birthdate": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.Lc7PFGL_OntmxgF6P_MCc2UgkbyBZ3B7T6_6zthfM-y95RvrCGFU5Q.CGH93N7ElvrcTHVkp8XUiQ.fwm8rH_cAQlnIFfpcRPs1A.dBKtapIrZiheaAeKcp63sA"
  }
}
```

The SD-JWT is then signed by the issuer to create a document like the following:

{#example-simple-sd-jwt-encoded}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInBtNGJPSEJnLW9ZaEF5UFd6U
jU2QVdYM3JVSVhwMTFfSUNEa0dnUzZXM1pXTHRzLWh6d0kzeDY1NjU5a2c0aFZvOWRiR29
DSkUzWkdGX2VhZXRFMzBVaEJVRWdwR3dyRHJRaUo5enFwcm1jRmZyM3F2dmtHanR0aDhaZ
2wxZU0yYkpjT3dFN1BDQkhXVEtXWXMxNTJSN2c2SmcyT1ZwaC1hOHJxLXE3OU1oS0c1UW9
XX21UejEwUVRfNkg0YzdQaldHMWZqaDhocFdObmJQX3B2NmQxelN3WmZjNWZsNnlWUkwwR
FYwVjNsR0hLZTJXcWZfZU5HakJyQkxWa2xEVGs4LXN0WF9NV0xjUi1FR21YQU92MFVCV2l
0U19kWEpLSnUtdlhKeXcxNG5IU0d1eFRJSzJoeDFwdHRNZnQ5Q3N2cWltWEtlRFRVMTRxU
UwxZUU3aWhjdyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAiX3NkIjogeyJzdWIiOiAiZXlKaGJHY2lPaUpCTVRJNFMxY2lMQ0psY
m1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4wLkpXQjVlTlN1cGpGbkZnaE0yVzBMZ0pHZm9
FVTFVMkg1VFpVZE43QlFvbEVBdVg1eThUdGdndy4ybDFUbUlYSW1fXzFzdWl0N1pXQ2t3L
k5ZUTZTZGJPOXpTdjdJZGZXNjBCRC1Ia0YwZVMzT1NXTG9VM19mV093M2Q4cDgxVExEWF9
pWmozc0VqRHJOWlIuaFZJeUxJak9FTWd3dTRPeHZrQVpjdyIsICJnaXZlbl9uYW1lIjogI
mV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC4
zLVB5SXJKOWpNV2FSR1o0em9JREY1VERXdEZrN2ZxUVdzUUVldURZbTNCZXg3SXk5bHFnY
WcuTTV6Mm56OEswNTVWckRFTmZaZmtudy5KS3c1c1pRTmxpZnRFaDZiVW85Y253LmptdWt
TQ29mQ05PZjV4NkM2OHI3amciLCAiZmFtaWx5X25hbWUiOiAiZXlKaGJHY2lPaUpCTVRJN
FMxY2lMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4wLmMxU1lDeFc4Tmk1MXpMU01
hYUx1YUdpMnh3WWhrOHFlWXpTS0p0Nnp5VGl0eGhGN05ES2IxZy52ZnRVek9nSXRCTDg0c
TUyTEhyaGRRLmtOT09NLUlTazFkNGdMSlhlMmJsZ2cudURpd1Q3NHphQWpmeFBhNE5SX21
OUSIsICJlbWFpbCI6ICJleUpoYkdjaU9pSkJNVEk0UzFjaUxDSmxibU1pT2lKQk1USTRRM
EpETFVoVE1qVTJJbjAuQUVjVDFDT0tVcGJBVkpFR2FhOFJCcnFwOVd5cFMxZlY5VUpSVFN
zWmRuMDRjSmoyRlpCLW5nLmxKb3AxWE5IM2NJa2loNmxKaUpEMEEucXloSDd3RHdiMlh1S
0VJbl9hUEJGMmVVOTBpSkRkRnRwWTNIN0pGbzFQQS5OTUpyNlQ4eS1mNjRKVXZjSGNIVTl
3IiwgInBob25lX251bWJlciI6ICJleUpoYkdjaU9pSkJNVEk0UzFjaUxDSmxibU1pT2lKQ
k1USTRRMEpETFVoVE1qVTJJbjAuaU1sdHZYMVNZRk9BRjlzdjF2MzhwNk1qU1ZFN0ZFbmR
2WE9CNXZrRUlrVEZaNXQ3a3RkNEJnLkUyMjQ3bjFoTlNuYy1tV19KSm50OWcuUmFBRUdGR
mc4dUw4UEVNZTBBUEl1RXNhbFhjOUh0dUxBeTVqUkpuZXNTby5uOFA4a1U3NUV4VWJQSUt
UM2hOSnFnIiwgImFkZHJlc3MiOiAiZXlKaGJHY2lPaUpCTVRJNFMxY2lMQ0psYm1NaU9pS
kJNVEk0UTBKRExVaFRNalUySW4wLldQMXY1ZU9OM3dIazhXSXZTeFdDT3NiWFhNQ1FRcDJ
BSXlmbHRrSXpRWW1hdC1ObVl0UlFxQS5pRWRvN0R4UTRtQ0dPUkJTSXBHcVVBLnBkWTh4a
EpXX0xpMS0zendKVUM2R3VpT0dpODloRXk4MUptd3d5Wl9yUGpDUkxQZ1JfNkNmX3owV29
ONkllUzBvNVIxallnMmctWlIzLUlXbmZnQXRmTWkycFpsaXZvSFAtd08xdEJaMEtUUWxRd
TU4ZEJCSmc5V1lSUjJvaks5LnU4YW01YTNXaXVJbFVnNWQxTTFDaGciLCAiYmlydGhkYXR
lIjogImV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVM
kluMC5MYzdQRkdMX09udG14Z0Y2UF9NQ2MyVWdrYnlCWjNCN1Q2XzZ6dGhmTS15OTVSdnJ
DR0ZVNVEuQ0dIOTNON0VsdnJjVEhWa3A4WFVpUS5md204ckhfY0FRbG5JRmZwY1JQczFBL
mRCS3RhcElyWmloZWFBZUtjcDYzc0EifX0.FrllCx-Sn0a-lFrBmFxjEiRZ5ryDPBSccF6
RBn_MenzoeRfqDm12ILXqVyTTbHmxTy7Q7sFqjQ5AnjER3cOJWPzBd_78PG8c5RzOwUUlG
fT_pgB98OV6yZfVdY49LBOme6npKfOsoc4xlZgJMUuXN7mCPSVOaGOSUKofPKNg-HRuM_t
63t_z0UoEeAQ3rS4rBGOVADBBxVKbJk9vzfUUIilIM0KUDu-8Q6qISX22Ahxu4U_CvXJrr
kcXnJ6acqqhyjhw_h7UbiYAhbUhEWmsjsMbtT8dks-kdfye3gOG32Md1k73b_Kife2McOF
j9a4bHqsyzHPTMjaRzlrcIwWVPw
```

(Line breaks for presentation only.)

### Example 2 - Structured SD-JWT

In this example, the issuer decided to create a structured object for the
hashes. This allows for the release of individual members of the address claim
separately.

The following is a non-normative example of the payload of an SD-JWT:

{#example-simple_structured-sd-jwt-payload}
```json
{
  "iss": "https://example.com/issuer",
  "sub_jwk": {
    "kty": "RSA",
    "n": "vPQMuX9esN_pRfYJaYbv0kn20HFuUFnC7YYvNjvTlHVfpQg8eGu0L0zj5BquDifOk-1Ftsk3yRe4yGhmoq6-JBpm57s4T6u3DAFvzIo_DcljJ6E3t7Kd-RUtx8dXYeI6ssWdTEvfppAbA26Ya5w0Bvo6P8PGsN3hMuNcsvyFJINXMzXJ3Ez_aenJ5Q-Yf0DM2S5bskhkxaAlW88sfj-Dx2o1QjJLNidTQnm6ypL-zVKSShtocim7ND7dgI8d_liNw6bd__xTf1LHuVrcHlDkOsT4EB-AeV9heMCHWgJHg89OS26HQJ6CXpFCSb5j91-1C8aK3zmMv_YMRudF2pTIfw",
    "e": "AQAB"
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "_sd": {
    "sub": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.eM6mCKS5FYDb6BHiBymHFikCHH7aQ88NeGGsdsbv-_Xm-yXDvHWpXg.K94QJYOtTwLCNPslhbaM0Q.BGhvn9YFi3GnNfj5uY28ltOKCl98j0H2nFkFMLtxG5mOUZgCxyz_DOBaifJH0yJu.Af6AxhXlZ3QMCjmfTecBVQ",
    "given_name": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.E0JiljoOqqARfcI4b-ovHuVk4xgyYF8QJjW6aNvxJ-TQVEW1JTlCKg.k8pu3qOeSnFYp-Tdglr3pA.Z9VebqYMv55Cx53rMUpo6g.x7qSZdXWZ1kNuNnM2GdUkQ",
    "family_name": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.nHK6e1Of_jUlG2KR2O5tE1BUTz9ClI63xYCw5SWbvOzNsdsk498nGw.KrrO8wdxtcDmqymMTT7noQ.UyXKpQSoXr9vxSlxWDIndg.FSApVaBo7sSSGWcDN1KZlQ",
    "email": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.h51ziZ4n816e5mWlxMBbIY8AypfqsFYaidUQxdIDlFfRj3VSsX5kLw.lyehOghIk-Setjs7hiw-AQ.ODC9D7oY-7k_Sr0P_XhCEVXceMTuLn2eJRct6cwO5g4.blzq_u3bpwa-JWLC9nBuTQ",
    "phone_number": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.J3yWsr47MfoO79PNEwJOr4xjhLwGRGNDLAT1QW4lsnt8jqx2YJZUtw.-ElRr9GnsH09YeDP9nJZKA.F2eEfcSL7WOj7Dse8W7BnptaFlL61FmEQUoVAfoBuvs.AN6Eh0I4MsISQ8zrbEVCNw",
    "address": {
      "street_address": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.xbxvmpBWwgCuJ9vPXWFkbWeXILvVkrIyXTRS5siRWuLVy64kd0ctGw.Jd7GdZgRec6ablJyuwrp9g.8WZJto-RnOrCH6psHS_99g.p_6JeDk-8kWG4D1mWrFZ6Q",
      "locality": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.XuYzOgcn_fI4IxVqK9zuMX0-L-_u3h3eSGutwxdwG5t1gd4dv89kVA.JeEhrO45VYhxkh6OiNi8Pg.WKQTksk9Wdyz4_lugokJZg.wulVLOCCBoqjPXgXbpLfgQ",
      "region": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.h-w8wMhBH_ga7fSCC4ekmC-Ax9aNUMDpphDkFyEn5fTXo9FzafxWcw.3vZXyfBgScdsWg-eyeq5SQ.Oq9miFtClca3w34qMxWYaQ.R52BZa0ivSQU-SzG6v2hsg",
      "country": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.CDqUzA0joLXTJe9xQeAk54zK2zCOV5e10YhnCL1Mc-RIpV_gdDLxDw.GTJxeP1fVlZlgB0fA_o62w.1SahaomWhJvD8SciK3Bo2g.0U8Mb9usMRoAvhVo87yzvw"
    },
    "birthdate": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.nTbxXAH_Mp8PROnVgT0EyhYmfR_6bTeukDKxC6xxpt1HjPANOmuAhQ.QVfz___bd3nSIF64n2toZw.WMwCPVSZYHzLP8Gc41123Q.K8RbaIyo_S7355Ogl3gLdQ"
  }
}
```

## Format of a SD-JWT Salt/Value Container (SVC)

Besides the SD-JWT itself, the holder needs to learn the raw claim values that
are contained in the SD-JWT, along with the precise input to the hash
calculation, and the salts. There MAY be other information the issuer needs to
communicate to the holder, such as a private key if the issuer selected the
holder key pair.

### SVC Claims

SVC can consist of the following claims.

#### `_sd` (Selectively Disclosable) Claim

A SD-JWT Salt/Value Container (SVC) is a JSON object containing at least the
top-level property `_sd`. Its structure mirrors the one of `_sd` in
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
    "sub": "QuI4XisbSkO32ypW4voiag",
    "given_name": "Vh0wQ1X3bqHhIQQnfByNfQ",
    "family_name": "n2IZLMNftNSpVggCsyRz2w",
    "email": "wnEFBWqwCPzCohIoo7WsuQ",
    "phone_number": "oldhx2AqKtdiBN55k0JCJg",
    "address": "ti_I41-VshpBcekK0fo5fg",
    "birthdate": "VOt2WrusoY5ohqkI5xou9g"
  }
}
```

### Example 2 - SVC for a Structured SD-JWT

The SVC for Example 2 is as follows:

{#example-simple_structured-svc-payload}
```json
{
  "_sd": {
    "sub": "kYMwtFdobtY9gfb6UrpbIQ",
    "given_name": "pgSR02-KJlANyOTIkgU3qQ",
    "family_name": "Su6tQTIUBZfuEfTNeWxjJg",
    "email": "XphLyRcfrjRaThT_NHgv-g",
    "phone_number": "idQm7a8ZP8HdHbXjUgdqBg",
    "address": {
      "street_address": "z7LsfZMmk92GxNq8yii9NQ",
      "locality": "ZhHRYPmH2y5OGGJ7LzFEgQ",
      "region": "lygcznWiuX2_9nYrCPWK5Q",
      "country": "pHbRe5XknQOxpg_xGDSUdA"
    },
    "birthdate": "ZR6msgsQ3-sCTTX9gyDpYQ"
  }
}
```

## Sending SD-JWT and SVC during Issuance

For transporting the SVC together with the SD-JWT from the issuer to the holder,
the SVC is base64url-encoded and appended to the SD-JWT using a period character `.` as the
separator. For Example 1, the combined format looks as follows:

{#example-simple-combined-sd-jwt-svc}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInBtNGJPSEJnLW9ZaEF5UFd6U
jU2QVdYM3JVSVhwMTFfSUNEa0dnUzZXM1pXTHRzLWh6d0kzeDY1NjU5a2c0aFZvOWRiR29
DSkUzWkdGX2VhZXRFMzBVaEJVRWdwR3dyRHJRaUo5enFwcm1jRmZyM3F2dmtHanR0aDhaZ
2wxZU0yYkpjT3dFN1BDQkhXVEtXWXMxNTJSN2c2SmcyT1ZwaC1hOHJxLXE3OU1oS0c1UW9
XX21UejEwUVRfNkg0YzdQaldHMWZqaDhocFdObmJQX3B2NmQxelN3WmZjNWZsNnlWUkwwR
FYwVjNsR0hLZTJXcWZfZU5HakJyQkxWa2xEVGs4LXN0WF9NV0xjUi1FR21YQU92MFVCV2l
0U19kWEpLSnUtdlhKeXcxNG5IU0d1eFRJSzJoeDFwdHRNZnQ5Q3N2cWltWEtlRFRVMTRxU
UwxZUU3aWhjdyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAiX3NkIjogeyJzdWIiOiAiZXlKaGJHY2lPaUpCTVRJNFMxY2lMQ0psY
m1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4wLkpXQjVlTlN1cGpGbkZnaE0yVzBMZ0pHZm9
FVTFVMkg1VFpVZE43QlFvbEVBdVg1eThUdGdndy4ybDFUbUlYSW1fXzFzdWl0N1pXQ2t3L
k5ZUTZTZGJPOXpTdjdJZGZXNjBCRC1Ia0YwZVMzT1NXTG9VM19mV093M2Q4cDgxVExEWF9
pWmozc0VqRHJOWlIuaFZJeUxJak9FTWd3dTRPeHZrQVpjdyIsICJnaXZlbl9uYW1lIjogI
mV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC4
zLVB5SXJKOWpNV2FSR1o0em9JREY1VERXdEZrN2ZxUVdzUUVldURZbTNCZXg3SXk5bHFnY
WcuTTV6Mm56OEswNTVWckRFTmZaZmtudy5KS3c1c1pRTmxpZnRFaDZiVW85Y253LmptdWt
TQ29mQ05PZjV4NkM2OHI3amciLCAiZmFtaWx5X25hbWUiOiAiZXlKaGJHY2lPaUpCTVRJN
FMxY2lMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4wLmMxU1lDeFc4Tmk1MXpMU01
hYUx1YUdpMnh3WWhrOHFlWXpTS0p0Nnp5VGl0eGhGN05ES2IxZy52ZnRVek9nSXRCTDg0c
TUyTEhyaGRRLmtOT09NLUlTazFkNGdMSlhlMmJsZ2cudURpd1Q3NHphQWpmeFBhNE5SX21
OUSIsICJlbWFpbCI6ICJleUpoYkdjaU9pSkJNVEk0UzFjaUxDSmxibU1pT2lKQk1USTRRM
EpETFVoVE1qVTJJbjAuQUVjVDFDT0tVcGJBVkpFR2FhOFJCcnFwOVd5cFMxZlY5VUpSVFN
zWmRuMDRjSmoyRlpCLW5nLmxKb3AxWE5IM2NJa2loNmxKaUpEMEEucXloSDd3RHdiMlh1S
0VJbl9hUEJGMmVVOTBpSkRkRnRwWTNIN0pGbzFQQS5OTUpyNlQ4eS1mNjRKVXZjSGNIVTl
3IiwgInBob25lX251bWJlciI6ICJleUpoYkdjaU9pSkJNVEk0UzFjaUxDSmxibU1pT2lKQ
k1USTRRMEpETFVoVE1qVTJJbjAuaU1sdHZYMVNZRk9BRjlzdjF2MzhwNk1qU1ZFN0ZFbmR
2WE9CNXZrRUlrVEZaNXQ3a3RkNEJnLkUyMjQ3bjFoTlNuYy1tV19KSm50OWcuUmFBRUdGR
mc4dUw4UEVNZTBBUEl1RXNhbFhjOUh0dUxBeTVqUkpuZXNTby5uOFA4a1U3NUV4VWJQSUt
UM2hOSnFnIiwgImFkZHJlc3MiOiAiZXlKaGJHY2lPaUpCTVRJNFMxY2lMQ0psYm1NaU9pS
kJNVEk0UTBKRExVaFRNalUySW4wLldQMXY1ZU9OM3dIazhXSXZTeFdDT3NiWFhNQ1FRcDJ
BSXlmbHRrSXpRWW1hdC1ObVl0UlFxQS5pRWRvN0R4UTRtQ0dPUkJTSXBHcVVBLnBkWTh4a
EpXX0xpMS0zendKVUM2R3VpT0dpODloRXk4MUptd3d5Wl9yUGpDUkxQZ1JfNkNmX3owV29
ONkllUzBvNVIxallnMmctWlIzLUlXbmZnQXRmTWkycFpsaXZvSFAtd08xdEJaMEtUUWxRd
TU4ZEJCSmc5V1lSUjJvaks5LnU4YW01YTNXaXVJbFVnNWQxTTFDaGciLCAiYmlydGhkYXR
lIjogImV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVM
kluMC5MYzdQRkdMX09udG14Z0Y2UF9NQ2MyVWdrYnlCWjNCN1Q2XzZ6dGhmTS15OTVSdnJ
DR0ZVNVEuQ0dIOTNON0VsdnJjVEhWa3A4WFVpUS5md204ckhfY0FRbG5JRmZwY1JQczFBL
mRCS3RhcElyWmloZWFBZUtjcDYzc0EifX0.FrllCx-Sn0a-lFrBmFxjEiRZ5ryDPBSccF6
RBn_MenzoeRfqDm12ILXqVyTTbHmxTy7Q7sFqjQ5AnjER3cOJWPzBd_78PG8c5RzOwUUlG
fT_pgB98OV6yZfVdY49LBOme6npKfOsoc4xlZgJMUuXN7mCPSVOaGOSUKofPKNg-HRuM_t
63t_z0UoEeAQ3rS4rBGOVADBBxVKbJk9vzfUUIilIM0KUDu-8Q6qISX22Ahxu4U_CvXJrr
kcXnJ6acqqhyjhw_h7UbiYAhbUhEWmsjsMbtT8dks-kdfye3gOG32Md1k73b_Kife2McOF
j9a4bHqsyzHPTMjaRzlrcIwWVPw.ewogICAgIl9zZCI6IHsKICAgICAgICAic3ViIjogIl
F1STRYaXNiU2tPMzJ5cFc0dm9pYWciLAogICAgICAgICJnaXZlbl9uYW1lIjogIlZoMHdR
MVgzYnFIaElRUW5mQnlOZlEiLAogICAgICAgICJmYW1pbHlfbmFtZSI6ICJuMklaTE1OZn
ROU3BWZ2dDc3lSejJ3IiwKICAgICAgICAiZW1haWwiOiAid25FRkJXcXdDUHpDb2hJb283
V3N1USIsCiAgICAgICAgInBob25lX251bWJlciI6ICJvbGRoeDJBcUt0ZGlCTjU1azBKQ0
pnIiwKICAgICAgICAiYWRkcmVzcyI6ICJ0aV9JNDEtVnNocEJjZWtLMGZvNWZnIiwKICAg
ICAgICAiYmlydGhkYXRlIjogIlZPdDJXcnVzb1k1b2hxa0k1eG91OWciCiAgICB9Cn0
```

(Line breaks for presentation only.)

## Format of an SD-JWT Release

SD-JWT-R contains claim values and the salts of the claims that the holder 
has consented to release to the Verifier. This enables the Verifier to verify 
the claims received from the holder by computing the hash sof the claims
values and the salts revealed in the SD-JWT-R using the hashing algorithm 
specified in SD-JWT and comparing them to the hash valued included in SD-JWT.

For each claim, an array of the salt and the claim value is contained in the
`_sd` object. The structure of `_sd` object in the SD-JWT-R is the same as in SD-JWT. 

The SD-JWT-R MAY contain further claims, for example, to ensure a binding
to a concrete transaction (in the example the `nonce` and `aud` claims).

The following is a non-normative example of the contents of an SD-JWT-R for Example 1:

{#example-simple-release-payload}
```json
{
  "nonce": "2GLC42sKQveCfGfryNRN9w",
  "aud": "https://example.com/verifier",
  "_sd": {
    "given_name": "Vh0wQ1X3bqHhIQQnfByNfQ",
    "family_name": "n2IZLMNftNSpVggCsyRz2w",
    "address": "ti_I41-VshpBcekK0fo5fg"
  }
}
``` 

The following is a non-normative example of an SD-JWT-R for SD-JWT in Example 2
that discloses only `region` and `country` of an `address` property:

{#example-simple_structured-release-payload}
```json
{
  "nonce": "2GLC42sKQveCfGfryNRN9w",
  "aud": "https://example.com/verifier",
  "_sd": {
    "given_name": "pgSR02-KJlANyOTIkgU3qQ",
    "family_name": "Su6tQTIUBZfuEfTNeWxjJg",
    "birthdate": "ZR6msgsQ3-sCTTX9gyDpYQ",
    "address": {
      "region": "lygcznWiuX2_9nYrCPWK5Q",
      "country": "pHbRe5XknQOxpg_xGDSUdA"
    }
  }
}
```

When the holder sends SD-JWT-R to the Verifier, it MUST be a JWS 
represented as the JWS Compact Serialization as described in 
Section 7.1 of [@!RFC7515].

If holder binding is desired, the SD-JWT-R is signed by the holder. If no
holder binding is to be used, the `none` algorithm is used, i.e., the document
is not signed.

Below is a non-normative example of a representation of SD-JWT-R for SD-JWT
given in Example 1 using JWS Compact Serialization:

{#example-simple-release-encoded}
```
eyJhbGciOiAiUlMyNTYifQ.eyJub25jZSI6ICIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3Iiw
gImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgIl9zZCI6IHsiZ2l2Z
W5fbmFtZSI6ICJWaDB3UTFYM2JxSGhJUVFuZkJ5TmZRIiwgImZhbWlseV9uYW1lIjogIm4
ySVpMTU5mdE5TcFZnZ0NzeVJ6MnciLCAiYWRkcmVzcyI6ICJ0aV9JNDEtVnNocEJjZWtLM
GZvNWZnIn19.kI8eqk-Eoy2BZvvDK2lqQmSLWe0mnbX3d5DOn92bHxRRvj4M2Uf0F6-W-l
J9DyfWRqSuROsB7vuvZVeuux76Um5u6LwZpMHVh3TiWjYKIfwvgnuy7hueeIS3bk_c0FCI
_SY9EeE-wE9CQcstVFuoAv2dcFdQB7LhULD3B8EpmZhDACxRlxBLjz9tIuO4g8zgqJ4mCL
6DrgCE_KlRLTyUiDH8Xfo8Yj0H7uImFWQ1fEDn6OJO91nUifN5LkOjBR09mH8bwZekLrN4
RwTL9hD9LQvVSWWQIVAs10w9Zx3gpWvy5RGQrh_gyLK0pSLmQydJjpGaox4vcIgjpgJyza
MTFQ
```

(Line breaks for presentation only.)

## Sending SD-JWT and SD-JWT-R during Presentation

The SD-JWT and the SD-JWT-R can be combined into one document using period character `.` as a separator (here for Example 1):

{#example-simple-combined-sd-jwt-sd-jwt-release}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInBtNGJPSEJnLW9ZaEF5UFd6U
jU2QVdYM3JVSVhwMTFfSUNEa0dnUzZXM1pXTHRzLWh6d0kzeDY1NjU5a2c0aFZvOWRiR29
DSkUzWkdGX2VhZXRFMzBVaEJVRWdwR3dyRHJRaUo5enFwcm1jRmZyM3F2dmtHanR0aDhaZ
2wxZU0yYkpjT3dFN1BDQkhXVEtXWXMxNTJSN2c2SmcyT1ZwaC1hOHJxLXE3OU1oS0c1UW9
XX21UejEwUVRfNkg0YzdQaldHMWZqaDhocFdObmJQX3B2NmQxelN3WmZjNWZsNnlWUkwwR
FYwVjNsR0hLZTJXcWZfZU5HakJyQkxWa2xEVGs4LXN0WF9NV0xjUi1FR21YQU92MFVCV2l
0U19kWEpLSnUtdlhKeXcxNG5IU0d1eFRJSzJoeDFwdHRNZnQ5Q3N2cWltWEtlRFRVMTRxU
UwxZUU3aWhjdyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAiX3NkIjogeyJzdWIiOiAiZXlKaGJHY2lPaUpCTVRJNFMxY2lMQ0psY
m1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4wLkpXQjVlTlN1cGpGbkZnaE0yVzBMZ0pHZm9
FVTFVMkg1VFpVZE43QlFvbEVBdVg1eThUdGdndy4ybDFUbUlYSW1fXzFzdWl0N1pXQ2t3L
k5ZUTZTZGJPOXpTdjdJZGZXNjBCRC1Ia0YwZVMzT1NXTG9VM19mV093M2Q4cDgxVExEWF9
pWmozc0VqRHJOWlIuaFZJeUxJak9FTWd3dTRPeHZrQVpjdyIsICJnaXZlbl9uYW1lIjogI
mV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC4
zLVB5SXJKOWpNV2FSR1o0em9JREY1VERXdEZrN2ZxUVdzUUVldURZbTNCZXg3SXk5bHFnY
WcuTTV6Mm56OEswNTVWckRFTmZaZmtudy5KS3c1c1pRTmxpZnRFaDZiVW85Y253LmptdWt
TQ29mQ05PZjV4NkM2OHI3amciLCAiZmFtaWx5X25hbWUiOiAiZXlKaGJHY2lPaUpCTVRJN
FMxY2lMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4wLmMxU1lDeFc4Tmk1MXpMU01
hYUx1YUdpMnh3WWhrOHFlWXpTS0p0Nnp5VGl0eGhGN05ES2IxZy52ZnRVek9nSXRCTDg0c
TUyTEhyaGRRLmtOT09NLUlTazFkNGdMSlhlMmJsZ2cudURpd1Q3NHphQWpmeFBhNE5SX21
OUSIsICJlbWFpbCI6ICJleUpoYkdjaU9pSkJNVEk0UzFjaUxDSmxibU1pT2lKQk1USTRRM
EpETFVoVE1qVTJJbjAuQUVjVDFDT0tVcGJBVkpFR2FhOFJCcnFwOVd5cFMxZlY5VUpSVFN
zWmRuMDRjSmoyRlpCLW5nLmxKb3AxWE5IM2NJa2loNmxKaUpEMEEucXloSDd3RHdiMlh1S
0VJbl9hUEJGMmVVOTBpSkRkRnRwWTNIN0pGbzFQQS5OTUpyNlQ4eS1mNjRKVXZjSGNIVTl
3IiwgInBob25lX251bWJlciI6ICJleUpoYkdjaU9pSkJNVEk0UzFjaUxDSmxibU1pT2lKQ
k1USTRRMEpETFVoVE1qVTJJbjAuaU1sdHZYMVNZRk9BRjlzdjF2MzhwNk1qU1ZFN0ZFbmR
2WE9CNXZrRUlrVEZaNXQ3a3RkNEJnLkUyMjQ3bjFoTlNuYy1tV19KSm50OWcuUmFBRUdGR
mc4dUw4UEVNZTBBUEl1RXNhbFhjOUh0dUxBeTVqUkpuZXNTby5uOFA4a1U3NUV4VWJQSUt
UM2hOSnFnIiwgImFkZHJlc3MiOiAiZXlKaGJHY2lPaUpCTVRJNFMxY2lMQ0psYm1NaU9pS
kJNVEk0UTBKRExVaFRNalUySW4wLldQMXY1ZU9OM3dIazhXSXZTeFdDT3NiWFhNQ1FRcDJ
BSXlmbHRrSXpRWW1hdC1ObVl0UlFxQS5pRWRvN0R4UTRtQ0dPUkJTSXBHcVVBLnBkWTh4a
EpXX0xpMS0zendKVUM2R3VpT0dpODloRXk4MUptd3d5Wl9yUGpDUkxQZ1JfNkNmX3owV29
ONkllUzBvNVIxallnMmctWlIzLUlXbmZnQXRmTWkycFpsaXZvSFAtd08xdEJaMEtUUWxRd
TU4ZEJCSmc5V1lSUjJvaks5LnU4YW01YTNXaXVJbFVnNWQxTTFDaGciLCAiYmlydGhkYXR
lIjogImV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVM
kluMC5MYzdQRkdMX09udG14Z0Y2UF9NQ2MyVWdrYnlCWjNCN1Q2XzZ6dGhmTS15OTVSdnJ
DR0ZVNVEuQ0dIOTNON0VsdnJjVEhWa3A4WFVpUS5md204ckhfY0FRbG5JRmZwY1JQczFBL
mRCS3RhcElyWmloZWFBZUtjcDYzc0EifX0.FrllCx-Sn0a-lFrBmFxjEiRZ5ryDPBSccF6
RBn_MenzoeRfqDm12ILXqVyTTbHmxTy7Q7sFqjQ5AnjER3cOJWPzBd_78PG8c5RzOwUUlG
fT_pgB98OV6yZfVdY49LBOme6npKfOsoc4xlZgJMUuXN7mCPSVOaGOSUKofPKNg-HRuM_t
63t_z0UoEeAQ3rS4rBGOVADBBxVKbJk9vzfUUIilIM0KUDu-8Q6qISX22Ahxu4U_CvXJrr
kcXnJ6acqqhyjhw_h7UbiYAhbUhEWmsjsMbtT8dks-kdfye3gOG32Md1k73b_Kife2McOF
j9a4bHqsyzHPTMjaRzlrcIwWVPw.eyJhbGciOiAiUlMyNTYifQ.eyJub25jZSI6ICIyR0x
DNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3Zlc
mlmaWVyIiwgIl9zZCI6IHsiZ2l2ZW5fbmFtZSI6ICJWaDB3UTFYM2JxSGhJUVFuZkJ5TmZ
RIiwgImZhbWlseV9uYW1lIjogIm4ySVpMTU5mdE5TcFZnZ0NzeVJ6MnciLCAiYWRkcmVzc
yI6ICJ0aV9JNDEtVnNocEJjZWtLMGZvNWZnIn19.kI8eqk-Eoy2BZvvDK2lqQmSLWe0mnb
X3d5DOn92bHxRRvj4M2Uf0F6-W-lJ9DyfWRqSuROsB7vuvZVeuux76Um5u6LwZpMHVh3Ti
WjYKIfwvgnuy7hueeIS3bk_c0FCI_SY9EeE-wE9CQcstVFuoAv2dcFdQB7LhULD3B8EpmZ
hDACxRlxBLjz9tIuO4g8zgqJ4mCL6DrgCE_KlRLTyUiDH8Xfo8Yj0H7uImFWQ1fEDn6OJO
91nUifN5LkOjBR09mH8bwZekLrN4RwTL9hD9LQvVSWWQIVAs10w9Zx3gpWvy5RGQrh_gyL
K0pSLmQydJjpGaox4vcIgjpgJyzaMTFQ
```

(Line breaks for presentation only.)

# Verification

Verifiers MUST follow [@RFC8725] for checking the SD-JWT and, if signed, the
SD-JWT Release.

Verifiers MUST go through (at least) the following steps before
trusting/using any of the contents of an SD-JWT:

 1. Determine if holder binding is to be checked for the SD-JWT. Refer to (#holder_binding_security) for details.
 2. Check that the presentation consists of six period-separated (`.`) elements; if holder binding is not required, the last element can be empty.
 3. Separate the SD-JWT from the SD-JWT Release.
 4. Validate the SD-JWT:
    1. Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [@RFC8725], Sections 3.1 and 3.2 for details.
    2. Validate the signature over the SD-JWT. 
    3. Validate the issuer of the SD-JWT and that the signing key belongs to this issuer.
    4. Check that the SD-JWT is valid using `nbf`, `iat`, and `exp` claims, if provided in the SD-JWT.
    5. Check that the claim `_sd` is present in the SD-JWT.
    6. Check the `hash_alg` claim and MUST accept only when the hash_alg is understand and deemed secure.
 5. Validate the SD-JWT Release:
    1. If holder binding is required, validate the signature over the SD-JWT using the same steps as for the SD-JWT plus the following steps:
       1. Determine that the public key for the private key that used to sign the SD-JWT-R is bound to the SD-JWT, i.e., the SD-JWT either contains a reference to the public key or contains the public key itself.
       2. Determine that the SD-JWT-R is bound to the current transaction and was created for this verifier (replay protection). This is usually achieved by a `nonce` and `aud` field within the SD-JWT Release.
    2. For each claim in the SD-JWT Release:
       1. Ensure that the claim is present as well in `_sd` in the SD-JWT.
          If `_sd` is structured, the claim MUST be present at the same
          place within the structure.
       2. Compute the base64url-encoded hash of a claim revealed from the Holder
          using the claim value and the salt included in the SD-JWT-R and 
          the `hash_alg` in SD-JWT.
       3. Compare the hah computed in the previous step with the hash of the same claim in SD-JWT. 
          Accept the claim only when the two hashes match.
       4. Ensure that the claim value in the SD-JWT-R is a JSON-encoded
          array of exactly two values.
       5. Store the second of the two values. 
    3. Once all necessary claims have been verified, their values can be
       validated and used according to the requirements of the application. It
       MUST be ensured that all claims required for the application have been
       released.

If any step fails, the input is not valid and processing MUST be aborted.


# Security Considerations {#security_considerations}

## Mandatory signing of the SD-JWT

The SD-JWT is MUST be signed by the issuer to protect integrity of the issued claims. An attacker may modify or add claims if an SD-JWT is not signed (e.g. change the "email" attribute to take over the victim's account, or add an attribute indicating a fake academic qualification).

The verifier MUST always check the SD_JWT signature to ensure that the SD-JWT has not been tampered with since its issuance. If the signature on the SD-JWT cannot be verified the SD-JWT MUST be rejected. 

## Entropy of the salt

The security model relies on the fact that the salt is not
learned or guessed by the attacker. It is vitally important to
adhere to this principle. As such, the salt has to be
created in such a manner that it is cryptographically random, long enough and has
high entropy that it is not practical for the attacker to guess.

## Choice of a hash function

For the security of this scheme, the hash function is required to have the following property.
Given a claim value, a salt, and the resulting hash, it is hard to find a second salt value 
so that HASH(salt | claim_value) equals the hash.

## Holder Binding {#holder_binding_security}


# Privacy Considerations {#privacy_considerations}

## Claim Names

Claim names are not hashed in the SD-JWT and are used as keys in a key-value pair, where the value is the hash.
This is because SD-JWT already reveals information about the issuer and the schema,
and revealing the claim names does not provide any additional information.

## Unlinkability 

It is also important to note that this format enables selective disclosure of claims, but
in itself it does not achieve unlinkability of the subject of an SD-SWT.


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

In this example, the Issuer is using a following object as a set of claims to issue to the Holder:

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
    "n": "xbFr2VpZ35E3PRZstEvkaoQCzyX11P3jvwv5IyLKdL7J5fgbUXxH2mD5h8SvTAJ_gkXPC7sy1cl4Rxesszy4PQA8KRay_tyTBIj-Cy3YQm0s5unDm9Ao2SYECgvXrDcULj2Zf7utCqfiWGle5MIkn5HU9uKMkZXp2aGv43GYrA-9uVvusFgsKc3NoKSQs3NeQ_VTGIph9Ty47kuXP6JzRdPb7_6IkGO6bghDeK4bP7542nuvh4oS1AVoyaQOgEoxlVS1m7C9Vnh3kO0L8H-0seKtIo_NtCpRnRMsi2wQeKyXZQpo0hWlK3lYfRx-6Px4oqWKtsBL-Feah2DcETjVAQ",
    "e": "AQAB"
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "_sd": {
    "verified_claims": {
      "verification": {
        "trust_framework": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.QU4_NbWFiHJVMb26PwjEICaxtUz-_uSK73cVAyJspLaa76MlqD7oPg.QISiXg3Zwh5SLmMZjz0vnA.yfatXHa3Pt-y47Cf3H4bMQ.JKQSwiQxcc6KV_qJXmVbUg",
        "time": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.OyAnzWBNezwaeb49s4p51EQ2CCk8LIITfX9Kz32pdBBaa1hbFm2D_g.xjnDHHuRCMP7WYWgJuGn4w.TfsTV5hfRezBs3zajIo1RSRdOawsFrCTFjR024qIDq8.bBIB06XbsQUdozjMz_0j0w",
        "verification_process": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.AFLAR_rSRZwSIAP3mbfOIvr_ZzxpTBNGL3YfkRRt30yuqm99MK_xoA.VsDsqtkfAP-eyQ17neB37A.3Gob5yIwREq5bp8Oqq8yBe6T-nmb5oMIyW25ajOxuRQtTxOj2t8pIrYGMda5MSK1.loECWnIjXkr2RxRucRHFWg",
        "evidence": [
          {
            "type": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.ASxYxGIuc8IjXkh4r8dbacuxUPLQGAimkjNjW31mv_ciIUDs4WcMng.-Jbs_6iyTENdSzYbn3lhPw.17vHtRLp5QhYt_ESWZcvYg.37fgirNSFPaT_ZnW2Y5sJA",
            "method": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.jMFqluAA6cIB9VlXYym9uBV5dOkwrqt1B0gTY4_wcqx5e4TWObVOoA.2vwR3GYHGZVQVjmQNobgGA.hB575_G3sh6eOr2ZMUm6iw.2Sy6EgH_dOwE9RY2H9kyHA",
            "time": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.8cKwOC7iwwWHxANEUnkcnBKH9qP45l6s8yX4fBlaAJo4glJh5SnLbA.IYW2KgTCixoVl33HK5OMTg.bTj_S4JCqbkZNjdiC6csMRXzV6ArybGhYlyCNQdmaE4.FP13qrI4F6nEoe5aC04jIw",
            "document": {
              "type": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.4lRaJc93ABgEWHfaT1472-g2Yi_0nTJXnEpnb4H3JH8vDm3CRCFhFA.T6vjZj82uwTZTClpw4oEKg.0_4Izs839yWMK88hI4RYkA.e6UI4ok1lACbtIt33Xhp_g",
              "issuer": {
                "name": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.gm--tAffPl-zb0FUUirgSq2ruYYfJMBU_PtyJbSJHlw9kB7h4LNq4g.6upnqE1MVES2B4jMpPNp1Q.fRnuwM0-MrsArcne7wf3ShRyRpB1LvAb2uNLCYjvrIY.oe51bGAnfaGxXpUfScCdTA",
                "country": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.kbehfPQS-arOiuCbFy2PfwdSYmPctuUNN5e1vy_UZ3Ctm06Xpm4hlw.lAqjCleAj_ceBkgNY7kkHQ.k8O2h1-4kMNEyin62I1kLg.2Mv0Gx47fhK_fVP8Jah_bA"
              },
              "number": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bNangiWonbxdV9EE65V6OlyjM6TdW4nFlNhRQG4etCtVb8ruPHDQCw.7zv3Fmr3zMQYfs1gJ1K4uw.KnS7JCsXVfrWku72mnRSKw.KIaVJ7R3tr3NscTSlUDBjg",
              "date_of_issuance": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bpa-QGEg9WiLO4vdJm9xSFHcCdjWDGZ_5uwHPaiZx_3nO5V0WvewYQ.4cPVnko7zqmOwOyQzYY3cg.S1-CmitLL8WPGiHHZbwwzw.GXf_SH0PlPHM9oryLnjeuA",
              "date_of_expiry": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.fYg9fyGDxIMdbkhibV6hN431mS_fCRIWud4CV7yMMSyc5NK0jh5_mQ.YFHxK-MdKZEFcQlAzcBoQg.lUk-f-_WZDJHP8ocPHf_hQ.NCHCwHaUUWyo0xtQoTNAdw"
            }
          }
        ]
      },
      "claims": {
        "given_name": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.3EvVbelu8Pcq5BDO4lhI_foTku9qnesppbAINH_j58CUWIRUCtzkiQ.TjCCTG7X7PAjDgL4jGTRSA.lOgTOZPDxw4drCjU8vGDcg.-sWCouF8EaKTQDnCu5J5Ag",
        "family_name": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.4-ru2AGTLrbFJf4230nZSQqWvHY0j7jdfXFeixsSRkMQa7Ri9N78gw.EdTDlNeDYMRI4mjYx7Z1ZQ.elqfT-GVZ50kc6F-spSrSw.Nf0CYm-LXiZ7HsBCCY2Msg",
        "birthdate": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.MfKYEdCKxtkDXl7sxE1koaQxuOp3dhVZDZQhSDZH2gdg13vZtPRucg.HBFS_piqAn3ri7vaEIUj9g.nTeAYzETPg2htuC88LBOXg.e1vD9ajph7SMnceqcHc0kg",
        "place_of_birth": {
          "country": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.GiCLJ79pvs8vLGlHEjtOkZvLyG9o17JedqgCsJXX2s-t0r8Y2ep7zw.5P0GP7lH-uqjDws55U65nQ.s7O5bWsC4wiy2xcaMxoYeQ.opPuAwcbklclhNsvwduW8Q",
          "locality": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.W9e0JvwKafOHwoLHkVkwkb-W5y4O_nRp3sxWJyME4CNr5kWCYfbf8w.99vdev7bnAOM3S_nzQkQ1g.g9uMFLpwhhuhPfUl49vpjw.V_GGjkgqCaQKmW7eGnoV9g"
        },
        "nationalities": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.Hfm58J4RrdWcdpAI2t7u0OVYLP3h8b9aneNEwVzsvBo7FlRL04IH5Q.ZJcNfVdygHHX_APezElThQ.Bu2D4dHKPWSucfzAFcbeqg.lw_TgOou1vO7lQHIV6VaxA",
        "address": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.0btoNz9r0R83y-CGY_eKc2eTHCCd50qxq7Ko0SgiKaBcQcmEBOVn3w.Cx8LyoCyDpWNbSEAwFUHBQ.77mzHy6wWQoyVRM0jU7UvkjAj1h3aoCKh4WAV_0F4OA8yoNgIbR49zrarcetefP9pTLv8YqJB2fE72BhIp8suAfAqHAZKuJBJHGMiCY47uRdOMKwa8RQ7e0BifZX2Vv3.Y1WovIj5DiCw29yvvCDs6A"
      }
    },
    "birth_middle_name": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.oRwyiEpcPJzYT5B9O5vOHQRNkaldNAUXM8PBXMrBHsxJTcobHm7zVA.f8A9G1BqcgDrgwTT0Grt8g.3zvl1_m3VQpiXux6aI5-dQ.1Nw0wgyp2TfddnbXre4x-Q",
    "salutation": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.nxUoUJmPLCO-_dKEbWgkrrrQ5l5YIaVOSYeaIu_c2rUbwyv-XUo_ow.P0cm4qzwsOxnV6Yt3sbC-g.oa2Zim80tv8BWj-pzT-FuQ.KMAKRvVXV9vetgc_HRcAyQ",
    "msisdn": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.lE0ZKgWFWURSUykyTM9O7r-TB4SUB1R7ym9FtALMmTA0dKe7MKbSyQ.ZC7RqhJPpx98Qz1_AWpuIQ.21ujpGPm5TAdtnlMaIobsQ.glibOxZg4RLVZ2p_zomr4g"
  }
}
```

The SD-JWT is then signed by the issuer to create a document like the following:

{#example-complex_structured-sd-jwt-encoded}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInhiRnIyVnBaMzVFM1BSWnN0R
XZrYW9RQ3p5WDExUDNqdnd2NUl5TEtkTDdKNWZnYlVYeEgybUQ1aDhTdlRBSl9na1hQQzd
zeTFjbDRSeGVzc3p5NFBRQThLUmF5X3R5VEJJai1DeTNZUW0wczV1bkRtOUFvMlNZRUNnd
lhyRGNVTGoyWmY3dXRDcWZpV0dsZTVNSWtuNUhVOXVLTWtaWHAyYUd2NDNHWXJBLTl1VnZ
1c0Znc0tjM05vS1NRczNOZVFfVlRHSXBoOVR5NDdrdVhQNkp6UmRQYjdfNklrR082YmdoR
GVLNGJQNzU0Mm51dmg0b1MxQVZveWFRT2dFb3hsVlMxbTdDOVZuaDNrTzBMOEgtMHNlS3R
Jb19OdENwUm5STXNpMndRZUt5WFpRcG8waFdsSzNsWWZSeC02UHg0b3FXS3RzQkwtRmVha
DJEY0VUalZBUSIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAiX3NkIjogeyJ2ZXJpZmllZF9jbGFpbXMiOiB7InZlcmlmaWNhdGlvb
iI6IHsidHJ1c3RfZnJhbWV3b3JrIjogImV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJtTWl
PaUpCTVRJNFEwSkRMVWhUTWpVMkluMC5RVTRfTmJXRmlISlZNYjI2UHdqRUlDYXh0VXotX
3VTSzczY1ZBeUpzcExhYTc2TWxxRDdvUGcuUUlTaVhnM1p3aDVTTG1NWmp6MHZuQS55ZmF
0WEhhM1B0LXk0N0NmM0g0Yk1RLkpLUVN3aVF4Y2M2S1ZfcUpYbVZiVWciLCAidGltZSI6I
CJleUpoYkdjaU9pSkJNVEk0UzFjaUxDSmxibU1pT2lKQk1USTRRMEpETFVoVE1qVTJJbjA
uT3lBbnpXQk5lendhZWI0OXM0cDUxRVEyQ0NrOExJSVRmWDlLejMycGRCQmFhMWhiRm0yR
F9nLnhqbkRISHVSQ01QN1dZV2dKdUduNHcuVGZzVFY1aGZSZXpCczN6YWpJbzFSU1JkT2F
3c0ZyQ1RGalIwMjRxSURxOC5iQklCMDZYYnNRVWRvempNel8wajB3IiwgInZlcmlmaWNhd
Glvbl9wcm9jZXNzIjogImV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJtTWlPaUpCTVRJNFE
wSkRMVWhUTWpVMkluMC5BRkxBUl9yU1Jad1NJQVAzbWJmT0l2cl9aenhwVEJOR0wzWWZrU
lJ0MzB5dXFtOTlNS194b0EuVnNEc3F0a2ZBUC1leVExN25lQjM3QS4zR29iNXlJd1JFcTV
icDhPcXE4eUJlNlQtbm1iNW9NSXlXMjVhak94dVJRdFR4T2oydDhwSXJZR01kYTVNU0sxL
mxvRUNXbklqWGtyMlJ4UnVjUkhGV2ciLCAiZXZpZGVuY2UiOiBbeyJ0eXBlIjogImV5Smh
iR2NpT2lKQk1USTRTMWNpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC5BU3hZe
EdJdWM4SWpYa2g0cjhkYmFjdXhVUExRR0FpbWtqTmpXMzFtdl9jaUlVRHM0V2NNbmcuLUp
ic182aXlURU5kU3pZYm4zbGhQdy4xN3ZIdFJMcDVRaFl0X0VTV1pjdllnLjM3Zmdpck5TR
lBhVF9ablcyWTVzSkEiLCAibWV0aG9kIjogImV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJ
tTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC5qTUZxbHVBQTZjSUI5VmxYWXltOXVCVjVkT
2t3cnF0MUIwZ1RZNF93Y3F4NWU0VFdPYlZPb0EuMnZ3UjNHWUhHWlZRVmptUU5vYmdHQS5
oQjU3NV9HM3NoNmVPcjJaTVVtNml3LjJTeTZFZ0hfZE93RTlSWTJIOWt5SEEiLCAidGltZ
SI6ICJleUpoYkdjaU9pSkJNVEk0UzFjaUxDSmxibU1pT2lKQk1USTRRMEpETFVoVE1qVTJ
JbjAuOGNLd09DN2l3d1dIeEFORVVua2NuQktIOXFQNDVsNnM4eVg0ZkJsYUFKbzRnbEpoN
VNuTGJBLklZVzJLZ1RDaXhvVmwzM0hLNU9NVGcuYlRqX1M0SkNxYmtaTmpkaUM2Y3NNUlh
6VjZBcnliR2hZbHlDTlFkbWFFNC5GUDEzcXJJNEY2bkVvZTVhQzA0akl3IiwgImRvY3VtZ
W50IjogeyJ0eXBlIjogImV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJtTWlPaUpCTVRJNFE
wSkRMVWhUTWpVMkluMC40bFJhSmM5M0FCZ0VXSGZhVDE0NzItZzJZaV8wblRKWG5FcG5iN
EgzSkg4dkRtM0NSQ0ZoRkEuVDZ2alpqODJ1d1RaVENscHc0b0VLZy4wXzRJenM4Mzl5V01
LODhoSTRSWWtBLmU2VUk0b2sxbEFDYnRJdDMzWGhwX2ciLCAiaXNzdWVyIjogeyJuYW1lI
jogImV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkl
uMC5nbS0tdEFmZlBsLXpiMEZVVWlyZ1NxMnJ1WVlmSk1CVV9QdHlKYlNKSGx3OWtCN2g0T
E5xNGcuNnVwbnFFMU1WRVMyQjRqTXBQTnAxUS5mUm51d00wLU1yc0FyY25lN3dmM1NoUnl
ScEIxTHZBYjJ1TkxDWWp2cklZLm9lNTFiR0FuZmFHeFhwVWZTY0NkVEEiLCAiY291bnRye
SI6ICJleUpoYkdjaU9pSkJNVEk0UzFjaUxDSmxibU1pT2lKQk1USTRRMEpETFVoVE1qVTJ
JbjAua2JlaGZQUVMtYXJPaXVDYkZ5MlBmd2RTWW1QY3R1VU5ONWUxdnlfVVozQ3RtMDZYc
G00aGx3LmxBcWpDbGVBal9jZUJrZ05ZN2trSFEuazhPMmgxLTRrTU5FeWluNjJJMWtMZy4
yTXYwR3g0N2ZoS19mVlA4SmFoX2JBIn0sICJudW1iZXIiOiAiZXlKaGJHY2lPaUpCTVRJN
FMxY2lMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4wLmJOYW5naVdvbmJ4ZFY5RUU
2NVY2T2x5ak02VGRXNG5GbE5oUlFHNGV0Q3RWYjhydVBIRFFDdy43enYzRm1yM3pNUVlmc
zFnSjFLNHV3LktuUzdKQ3NYVmZyV2t1NzJtblJTS3cuS0lhVko3UjN0cjNOc2NUU2xVREJ
qZyIsICJkYXRlX29mX2lzc3VhbmNlIjogImV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJtT
WlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC5icGEtUUdFZzlXaUxPNHZkSm05eFNGSGNDZGp
XREdaXzV1d0hQYWlaeF8zbk81VjBXdmV3WVEuNGNQVm5rbzd6cW1Pd095UXpZWTNjZy5TM
S1DbWl0TEw4V1BHaUhIWmJ3d3p3LkdYZl9TSDBQbFBITTlvcnlMbmpldUEiLCAiZGF0ZV9
vZl9leHBpcnkiOiAiZXlKaGJHY2lPaUpCTVRJNFMxY2lMQ0psYm1NaU9pSkJNVEk0UTBKR
ExVaFRNalUySW4wLmZZZzlmeUdEeElNZGJraGliVjZoTjQzMW1TX2ZDUklXdWQ0Q1Y3eU1
NU3ljNU5LMGpoNV9tUS5ZRkh4Sy1NZEtaRUZjUWxBemNCb1FnLmxVay1mLV9XWkRKSFA4b
2NQSGZfaFEuTkNIQ3dIYVVVV3lvMHh0UW9UTkFkdyJ9fV19LCAiY2xhaW1zIjogeyJnaXZ
lbl9uYW1lIjogImV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJtTWlPaUpCTVRJNFEwSkRMV
WhUTWpVMkluMC4zRXZWYmVsdThQY3E1QkRPNGxoSV9mb1RrdTlxbmVzcHBiQUlOSF9qNTh
DVVdJUlVDdHpraVEuVGpDQ1RHN1g3UEFqRGdMNGpHVFJTQS5sT2dUT1pQRHh3NGRyQ2pVO
HZHRGNnLi1zV0NvdUY4RWFLVFFEbkN1NUo1QWciLCAiZmFtaWx5X25hbWUiOiAiZXlKaGJ
HY2lPaUpCTVRJNFMxY2lMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4wLjQtcnUyQ
UdUTHJiRkpmNDIzMG5aU1FxV3ZIWTBqN2pkZlhGZWl4c1NSa01RYTdSaTlONzhndy5FZFR
EbE5lRFlNUkk0bWpZeDdaMVpRLmVscWZULUdWWjUwa2M2Ri1zcFNyU3cuTmYwQ1ltLUxYa
Vo3SHNCQ0NZMk1zZyIsICJiaXJ0aGRhdGUiOiAiZXlKaGJHY2lPaUpCTVRJNFMxY2lMQ0p
sYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4wLk1mS1lFZENLeHRrRFhsN3N4RTFrb2FRe
HVPcDNkaFZaRFpRaFNEWkgyZ2RnMTN2WnRQUnVjZy5IQkZTX3BpcUFuM3JpN3ZhRUlVajl
nLm5UZUFZekVUUGcyaHR1Qzg4TEJPWGcuZTF2RDlhanBoN1NNbmNlcWNIYzBrZyIsICJwb
GFjZV9vZl9iaXJ0aCI6IHsiY291bnRyeSI6ICJleUpoYkdjaU9pSkJNVEk0UzFjaUxDSmx
ibU1pT2lKQk1USTRRMEpETFVoVE1qVTJJbjAuR2lDTEo3OXB2czh2TEdsSEVqdE9rWnZMe
Uc5bzE3SmVkcWdDc0pYWDJzLXQwcjhZMmVwN3p3LjVQMEdQN2xILXVxakR3czU1VTY1blE
uczdPNWJXc0M0d2l5MnhjYU14b1llUS5vcFB1QXdjYmtsY2xoTnN2d2R1VzhRIiwgImxvY
2FsaXR5IjogImV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWh
UTWpVMkluMC5XOWUwSnZ3S2FmT0h3b0xIa1Zrd2tiLVc1eTRPX25ScDNzeFdKeU1FNENOc
jVrV0NZZmJmOHcuOTl2ZGV2N2JuQU9NM1NfbnpRa1ExZy5nOXVNRkxwd2hodWhQZlVsNDl
2cGp3LlZfR0dqa2dxQ2FRS21XN2VHbm9WOWcifSwgIm5hdGlvbmFsaXRpZXMiOiAiZXlKa
GJHY2lPaUpCTVRJNFMxY2lMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4wLkhmbTU
4SjRScmRXY2RwQUkydDd1ME9WWUxQM2g4YjlhbmVORXdWenN2Qm83RmxSTDA0SUg1US5aS
mNOZlZkeWdISFhfQVBlekVsVGhRLkJ1MkQ0ZEhLUFdTdWNmekFGY2JlcWcubHdfVGdPb3U
xdk83bFFISVY2VmF4QSIsICJhZGRyZXNzIjogImV5SmhiR2NpT2lKQk1USTRTMWNpTENKb
GJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC4wYnRvTno5cjBSODN5LUNHWV9lS2MyZVR
IQ0NkNTBxeHE3S28wU2dpS2FCY1FjbUVCT1ZuM3cuQ3g4THlvQ3lEcFdOYlNFQXdGVUhCU
S43N216SHk2d1dRb3lWUk0walU3VXZrakFqMWgzYW9DS2g0V0FWXzBGNE9BOHlvTmdJYlI
0OXpyYXJjZXRlZlA5cFRMdjhZcUpCMmZFNzJCaElwOHN1QWZBcUhBWkt1SkJKSEdNaUNZN
Dd1UmRPTUt3YThSUTdlMEJpZlpYMlZ2My5ZMVdvdklqNURpQ3cyOXl2dkNEczZBIn19LCA
iYmlydGhfbWlkZGxlX25hbWUiOiAiZXlKaGJHY2lPaUpCTVRJNFMxY2lMQ0psYm1NaU9pS
kJNVEk0UTBKRExVaFRNalUySW4wLm9Sd3lpRXBjUEp6WVQ1QjlPNXZPSFFSTmthbGROQVV
YTThQQlhNckJIc3hKVGNvYkhtN3pWQS5mOEE5RzFCcWNnRHJnd1RUMEdydDhnLjN6dmwxX
20zVlFwaVh1eDZhSTUtZFEuMU53MHdneXAyVGZkZG5iWHJlNHgtUSIsICJzYWx1dGF0aW9
uIjogImV5SmhiR2NpT2lKQk1USTRTMWNpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVM
kluMC5ueFVvVUptUExDTy1fZEtFYldna3JyclE1bDVZSWFWT1NZZWFJdV9jMnJVYnd5di1
YVW9fb3cuUDBjbTRxendzT3huVjZZdDNzYkMtZy5vYTJaaW04MHR2OEJXai1welQtRnVRL
ktNQUtSdlZYVjl2ZXRnY19IUmNBeVEiLCAibXNpc2RuIjogImV5SmhiR2NpT2lKQk1USTR
TMWNpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC5sRTBaS2dXRldVUlNVeWt5V
E05TzdyLVRCNFNVQjFSN3ltOUZ0QUxNbVRBMGRLZTdNS2JTeVEuWkM3UnFoSlBweDk4UXo
xX0FXcHVJUS4yMXVqcEdQbTVUQWR0bmxNYUlvYnNRLmdsaWJPeFpnNFJMVloycF96b21yN
GcifX0.M2AT3OtHLXI7_HZAuvyoDVaOknpRnvrsAet-uvUj_LmRq1qW0x59BvgX_8wLNsN
uRWCUqUijFnjVRjvUMt08YrPWV2pZeGjO3novHOYxouqjtiu05TBArYXCnolBivUNkRbfz
mlBIUH5l0frvnO58EWN4i6O6azupIYeGwoqMOnqsNcnXzyoBOqohX_8K9PRw6CjMfzgzfn
cFiiqT20iesbz19T6HERsIIgN0rTh9KHuIUbKs9g8StCwU3ShO-4n3kZ7-p7bziO4Dih2s
A4ETFwMqkp22CIjpUqX-BWgv6fqb-Kr109b2ePcuNtkpK7636lAKmgADQxLPx7lrLq9Jg.
ewogICAgIl9zZCI6IHsKICAgICAgICAidmVyaWZpZWRfY2xhaW1zIjogewogICAgICAgIC
AgICAidmVyaWZpY2F0aW9uIjogewogICAgICAgICAgICAgICAgInRydXN0X2ZyYW1ld29y
ayI6ICJfRm10YTNZV0VMRFNCeFprUEtHcXRnIiwKICAgICAgICAgICAgICAgICJ0aW1lIj
ogIkI0RVZFSkg5cDc1UWc0RjFURTIzUFEiLAogICAgICAgICAgICAgICAgInZlcmlmaWNh
dGlvbl9wcm9jZXNzIjogImJJNlREWmFTR1hockZzMDhLTi1uN2ciLAogICAgICAgICAgIC
AgICAgImV2aWRlbmNlIjogWwogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAg
ICAgICAgICAgICAgInR5cGUiOiAiaDl5UWdyUzZGVWNsVHBqbVdaYU15dyIsCiAgICAgIC
AgICAgICAgICAgICAgICAgICJtZXRob2QiOiAiZ1Z5UmxwM0R6cG4xTE52b212dEpIdyIs
CiAgICAgICAgICAgICAgICAgICAgICAgICJ0aW1lIjogInRPVU11OHZ1dlcwQkVOS2J3UX
FnQXciLAogICAgICAgICAgICAgICAgICAgICAgICAiZG9jdW1lbnQiOiB7CiAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAidHlwZSI6ICJ1Yl9qMGcwY3NGWlIzU0hJMkhyRk93Ii
wKICAgICAgICAgICAgICAgICAgICAgICAgICAgICJpc3N1ZXIiOiB7CiAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgIm5hbWUiOiAiMDd1WU9xVUNzXzJfRlNGQl9YeURndy
IsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImNvdW50cnkiOiAiZThkaEst
dXlPRkpMS0tSUElnZnl0dyIKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0sCiAgIC
AgICAgICAgICAgICAgICAgICAgICAgICAibnVtYmVyIjogInRwSWQ3dENrYTl1cVEybjRq
U3N5Z1EiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgImRhdGVfb2ZfaXNzdWFuY2
UiOiAiYVMyX3ZMYTJhbWdEZmIxQ2FPV3lBZyIsCiAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAiZGF0ZV9vZl9leHBpcnkiOiAidk9mS2x1dmNoY01Mc0pVd2JBMmxTdyIKICAgIC
AgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAg
ICAgICAgIF0KICAgICAgICAgICAgfSwKICAgICAgICAgICAgImNsYWltcyI6IHsKICAgIC
AgICAgICAgICAgICJnaXZlbl9uYW1lIjogImF2OHJNTm1EZEUwd2I0bGlIMWZ6S2ciLAog
ICAgICAgICAgICAgICAgImZhbWlseV9uYW1lIjogIlFQNmM4UWxfVFdMZlV5YmlXNVMwSU
EiLAogICAgICAgICAgICAgICAgImJpcnRoZGF0ZSI6ICJxSE9GVng2MzE5TV82VmFuUE9O
TURnIiwKICAgICAgICAgICAgICAgICJwbGFjZV9vZl9iaXJ0aCI6IHsKICAgICAgICAgIC
AgICAgICAgICAiY291bnRyeSI6ICI1ZXNpR0daMUhwb1cwUUE5Wm1pMHV3IiwKICAgICAg
ICAgICAgICAgICAgICAibG9jYWxpdHkiOiAiRFlDTFJBS2kteUtzdVphdGMxZ2JFQSIKIC
AgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICAibmF0aW9uYWxpdGllcyI6ICJV
ZDhWV20xVmxraGRlWEVxWEZ3Rzh3IiwKICAgICAgICAgICAgICAgICJhZGRyZXNzIjogIl
ZSZ003WldsRTg2WlNjN3lFSExDWVEiCiAgICAgICAgICAgIH0KICAgICAgICB9LAogICAg
ICAgICJiaXJ0aF9taWRkbGVfbmFtZSI6ICJBR2kxTlh2Skx4Z0cwdFczUkZRWE5RIiwKIC
AgICAgICAic2FsdXRhdGlvbiI6ICJtUVh6VHROOTg3dlhxa1U4WFJUOC13IiwKICAgICAg
ICAibXNpc2RuIjogIm1SZGMtTXJnRUFfN3hQZTFvc1RnV3ciCiAgICB9Cn0
```

(Line breaks for presentation only.)

A SD-JWT-R for some of the claims:

{#example-complex_structured-release-payload}
```json
{
  "nonce": "2GLC42sKQveCfGfryNRN9w",
  "aud": "https://example.com/verifier",
  "_sd": {
    "verified_claims": {
      "verification": {
        "trust_framework": "_Fmta3YWELDSBxZkPKGqtg",
        "time": "B4EVEJH9p75Qg4F1TE23PQ",
        "evidence": [
          {
            "type": "h9yQgrS6FUclTpjmWZaMyw"
          }
        ]
      },
      "claims": {
        "given_name": "av8rMNmDdE0wb4liH1fzKg",
        "family_name": "QP6c8Ql_TWLfUybiW5S0IA",
        "birthdate": "qHOFVx6319M_6VanPONMDg",
        "place_of_birth": {
          "country": "5esiGGZ1HpoW0QA9Zmi0uw"
        }
      }
    }
  }
}
```

## Example 4 - W3C Verifiable Credentials Data Model

This example issustrates how this artifacts defined in this specification 
can be represented using W3C Verifiable Credentials Data Model as defined in [@!VC-DATA-MODEL].

Below is a non-normative example of an SD-JWT represented as a verifiable credential 
encoded as JSON and signed as JWS compliant to [@!VC-DATA-MODEL].

SVC sent alongside this SD-JWT as a JWT-VC is same as in Example 1.

```json
{
  "sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
  "jti": "http://example.edu/credentials/3732",
  "iss": "https://example.com/keys/foo.jwk",
  "nbf": 1541493724,
  "iat": 1541493724,
  "exp": 1573029723,
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "type": [
      "VerifiableCredential",
      "UniversityDegreeCredential"
    ]
  },
  "_sd": {
    "given_name": "fUMdn88aaoyKTHrvZd6AuLmPraGhPJ0zF5r_JhxCVZs",
    "family_name": "9h5vgv6TpFV6GmnPtugiMLl5tHetHeb5X_2cKHjN7cw",
    "birthdate": "fvLCnDm3r4VSYcBF3pIlXP4ulEoHuHOfG_YmFZEuxpQ"
  }
}
```

Below is a non-normative example of an SD-JWT-R represented as a verifiable presentation
encoded as JSON and signed as a JWS compliant to [@!VC-DATA-MODEL].

```json
{
  "iss": "did:example:ebfeb1f712ebc6f1c276e12ec21",
  "aud": "s6BhdRkqt3",
  "nbf": 1560415047,
  "iat": 1560415047,
  "exp": 1573029723,
  "nonce": "660!6345FSer",
  "vp": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1"
    ],
    "type": [
      "VerifiablePresentation"
    ],
    "verifiableCredential": ["eyJhb...npyXw"]
  },
  "_sd": {
    "given_name": "[\"6Ij7tM-a5iVPGboS5tmvVA\", \"John\"]",
    "family_name": "[\"eI8ZWm9QnKPpNPeNenHdhQ\", \"Doe\"]",
    "birthdate": "[\"5bPs1IquZNa0hkaFzzzZNw\", \"1940-01-01\"]"
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

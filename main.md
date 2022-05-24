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
        "n": "sGUW8r_eit3aSqpqEjSCGwGLLkZ1fVlN5fMdfRRVcohrk4094cezNIqqAYKf4oFUV5uT9G-Csk28HSyMKjYQZZQTQWiC9FazT1lo9t-U1MoRQ3DVJ8WOyeh9naLFo2gHojIlnnyzcsUat5BRO1eJsoe61gLGxnI01bxaViY_baDXobCGhFOOcD10-nYK6KqxYPlwVbn0yA28t1zJuxUr0CNFS4VdV1EuBjGAu3tZdvUDvJ3xQ-IXI1acTNKS10W7yI_jXk9MfCtWXazrvLa-vpt7Rs_-jvBCpg6OvriEm86IhZGneWF5EImYXkCkIWilJhNJ7JzXpt7mkc4OFq3bpw",
        "e": "AQAB"
    },
    "iat": 1516239022,
    "exp": 1516247022,
    "sd_claims": {
        "sub": "yl_P7wXasmncw5Ms9lguAjnP136bSczze990YWSN7x8",
        "given_name": "fXhflWDu0FhjpTHyB1u9e_mTDStGC-C3QZys-jmFPRs",
        "family_name": "46EvOcgECtb0Z5yHgvt00b_A5jiIsnwid8cNZnEnNEs",
        "email": "CyjswRTCzgzEYxIuuy4Iow2WIo_-eA37bt_4o8Sq3k8",
        "phone_number": "wFcES2Vo-qewhpzsi9R4v0BictRUuXx4cte5bo_O0KY",
        "address": "3aMnm2MYwuFIsne-RavzKooNuoUq7_K4dvGfsGK5vLQ",
        "birthdate": "Y9LB-Up8ZOK0lLWNWqcvPQxojI5BhT6eK_pyZlEYQyM"
    }
}
```

The SD-JWT is then signed by the issuer to create a document like the following:

{#example-sd-jwt-encoded}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInNHVVc4cl9laXQzYVNxcHFFa
lNDR3dHTExrWjFmVmxONWZNZGZSUlZjb2hyazQwOTRjZXpOSXFxQVlLZjRvRlVWNXVUOUc
tQ3NrMjhIU3lNS2pZUVpaUVRRV2lDOUZhelQxbG85dC1VMU1vUlEzRFZKOFdPeWVoOW5hT
EZvMmdIb2pJbG5ueXpjc1VhdDVCUk8xZUpzb2U2MWdMR3huSTAxYnhhVmlZX2JhRFhvYkN
HaEZPT2NEMTAtbllLNktxeFlQbHdWYm4weUEyOHQxekp1eFVyMENORlM0VmRWMUV1QmpHQ
XUzdFpkdlVEdkozeFEtSVhJMWFjVE5LUzEwVzd5SV9qWGs5TWZDdFdYYXpydkxhLXZwdDd
Sc18tanZCQ3BnNk92cmlFbTg2SWhaR25lV0Y1RUltWVhrQ2tJV2lsSmhOSjdKelhwdDdta
2M0T0ZxM2JwdyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAic2RfY2xhaW1zIjogeyJzdWIiOiAieWxfUDd3WGFzbW5jdzVNczlsZ
3VBam5QMTM2YlNjenplOTkwWVdTTjd4OCIsICJnaXZlbl9uYW1lIjogImZYaGZsV0R1MEZ
oanBUSHlCMXU5ZV9tVERTdEdDLUMzUVp5cy1qbUZQUnMiLCAiZmFtaWx5X25hbWUiOiAiN
DZFdk9jZ0VDdGIwWjV5SGd2dDAwYl9BNWppSXNud2lkOGNOWm5Fbk5FcyIsICJlbWFpbCI
6ICJDeWpzd1JUQ3pnekVZeEl1dXk0SW93MldJb18tZUEzN2J0XzRvOFNxM2s4IiwgInBob
25lX251bWJlciI6ICJ3RmNFUzJWby1xZXdocHpzaTlSNHYwQmljdFJVdVh4NGN0ZTVib19
PMEtZIiwgImFkZHJlc3MiOiAiM2FNbm0yTVl3dUZJc25lLVJhdnpLb29OdW9VcTdfSzRkd
kdmc0dLNXZMUSIsICJiaXJ0aGRhdGUiOiAiWTlMQi1VcDhaT0swbExXTldxY3ZQUXhvakk
1QmhUNmVLX3B5WmxFWVF5TSJ9fQ.qbhmSxY0KTnW4J6tdLRZeKucgc3srozxzyKTwFK199
VmrQfRZ2NXbt9yyg0we44mxv_4o7O7TvH9fsy9CZ1OcNDVDjHEZi0JcixtST0z_KsU1AHp
ODqy0TyCcMUDFcb43nSQ-Or8EX5HdiFjmu1nn8sr24HwpCAQHO8MRDdtoXYx-sgWysIE_q
qagyveoZxuB7bl-rLbFgusJNTE2NZr5cUso57_Zg6lQrxcysuZInwYkxa2SCUY56tFX3xJ
_zYdZx3H4MkLMMlFc2f6z37Pl6zUZFSj7LakWBdq9-eevcw-dGhzEPeETl6ltofJ5NZaDL
HJ8ooIL5z4cmRrd4KBKg.ewogICAgInNkX2NsYWltcyI6IHsKICAgICAgICAic3ViIjogI
ltcIkhFM29QUkE5MjRMOFJjNXFobzcxMndcIiwgXCI2YzVjMGE0OS1iNTg5LTQzMWQtYmF
lNy0yMTkxMjJhOWVjMmNcIl0iLAogICAgICAgICJnaXZlbl9uYW1lIjogIltcImI2VGtqb
2ZXU1I5VUV3LTVLalVNaEFcIiwgXCJKb2huXCJdIiwKICAgICAgICAiZmFtaWx5X25hbWU
iOiAiW1wiZXl3ajBLY1ljZE40N1NKTnAzamJmQVwiLCBcIkRvZVwiXSIsCiAgICAgICAgI
mVtYWlsIjogIltcIlNLOEM5ZndONjhTV2toR3FtdTVLMWdcIiwgXCJqb2huZG9lQGV4YW1
wbGUuY29tXCJdIiwKICAgICAgICAicGhvbmVfbnVtYmVyIjogIltcIktJSk5KcXZfNnR3Z
FVYNGZvdGExSlFcIiwgXCIrMS0yMDItNTU1LTAxMDFcIl0iLAogICAgICAgICJhZGRyZXN
zIjogIltcInNSd3NPU3Vuek5vdkVMSFF6SHVoRXdcIiwge1wic3RyZWV0X2FkZHJlc3NcI
jogXCIxMjMgTWFpbiBTdFwiLCBcImxvY2FsaXR5XCI6IFwiQW55dG93blwiLCBcInJlZ2l
vblwiOiBcIkFueXN0YXRlXCIsIFwiY291bnRyeVwiOiBcIlVTXCJ9XSIsCiAgICAgICAgI
mJpcnRoZGF0ZSI6ICJbXCJRc0RlMnJpWWJDTERtUmUydXZDZGRBXCIsIFwiMTk0MC0wMS0
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
        "sub": "[\"HE3oPRA924L8Rc5qho712w\", \"6c5c0a49-b589-431d-bae7-219122a9ec2c\"]",
        "given_name": "[\"b6TkjofWSR9UEw-5KjUMhA\", \"John\"]",
        "family_name": "[\"eywj0KcYcdN47SJNp3jbfA\", \"Doe\"]",
        "email": "[\"SK8C9fwN68SWkhGqmu5K1g\", \"johndoe@example.com\"]",
        "phone_number": "[\"KIJNJqv_6twdUX4fota1JQ\", \"+1-202-555-0101\"]",
        "address": "[\"sRwsOSunzNovELHQzHuhEw\", {\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}]",
        "birthdate": "[\"QsDe2riYbCLDmRe2uvCddA\", \"1940-01-01\"]"
    }
}
```

## SD-JWT and SVC Combined Format

For transporting the SVC together with the SD-JWT from the issuer to the holder,
the SVC is BASE64URL encoded and appended to the SD-JWT using `.` as the
separator:

{#example-combined-encoded}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInNHVVc4cl9laXQzYVNxcHFFa
lNDR3dHTExrWjFmVmxONWZNZGZSUlZjb2hyazQwOTRjZXpOSXFxQVlLZjRvRlVWNXVUOUc
tQ3NrMjhIU3lNS2pZUVpaUVRRV2lDOUZhelQxbG85dC1VMU1vUlEzRFZKOFdPeWVoOW5hT
EZvMmdIb2pJbG5ueXpjc1VhdDVCUk8xZUpzb2U2MWdMR3huSTAxYnhhVmlZX2JhRFhvYkN
HaEZPT2NEMTAtbllLNktxeFlQbHdWYm4weUEyOHQxekp1eFVyMENORlM0VmRWMUV1QmpHQ
XUzdFpkdlVEdkozeFEtSVhJMWFjVE5LUzEwVzd5SV9qWGs5TWZDdFdYYXpydkxhLXZwdDd
Sc18tanZCQ3BnNk92cmlFbTg2SWhaR25lV0Y1RUltWVhrQ2tJV2lsSmhOSjdKelhwdDdta
2M0T0ZxM2JwdyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAic2RfY2xhaW1zIjogeyJzdWIiOiAieWxfUDd3WGFzbW5jdzVNczlsZ
3VBam5QMTM2YlNjenplOTkwWVdTTjd4OCIsICJnaXZlbl9uYW1lIjogImZYaGZsV0R1MEZ
oanBUSHlCMXU5ZV9tVERTdEdDLUMzUVp5cy1qbUZQUnMiLCAiZmFtaWx5X25hbWUiOiAiN
DZFdk9jZ0VDdGIwWjV5SGd2dDAwYl9BNWppSXNud2lkOGNOWm5Fbk5FcyIsICJlbWFpbCI
6ICJDeWpzd1JUQ3pnekVZeEl1dXk0SW93MldJb18tZUEzN2J0XzRvOFNxM2s4IiwgInBob
25lX251bWJlciI6ICJ3RmNFUzJWby1xZXdocHpzaTlSNHYwQmljdFJVdVh4NGN0ZTVib19
PMEtZIiwgImFkZHJlc3MiOiAiM2FNbm0yTVl3dUZJc25lLVJhdnpLb29OdW9VcTdfSzRkd
kdmc0dLNXZMUSIsICJiaXJ0aGRhdGUiOiAiWTlMQi1VcDhaT0swbExXTldxY3ZQUXhvakk
1QmhUNmVLX3B5WmxFWVF5TSJ9fQ.qbhmSxY0KTnW4J6tdLRZeKucgc3srozxzyKTwFK199
VmrQfRZ2NXbt9yyg0we44mxv_4o7O7TvH9fsy9CZ1OcNDVDjHEZi0JcixtST0z_KsU1AHp
ODqy0TyCcMUDFcb43nSQ-Or8EX5HdiFjmu1nn8sr24HwpCAQHO8MRDdtoXYx-sgWysIE_q
qagyveoZxuB7bl-rLbFgusJNTE2NZr5cUso57_Zg6lQrxcysuZInwYkxa2SCUY56tFX3xJ
_zYdZx3H4MkLMMlFc2f6z37Pl6zUZFSj7LakWBdq9-eevcw-dGhzEPeETl6ltofJ5NZaDL
HJ8ooIL5z4cmRrd4KBKg.eyJhbGciOiAiUlMyNTYifQ.eyJub25jZSI6ICJFSG9iaWVZTV
pxTFBZRGZGSjVkSkFBIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVy
IiwgInNkX2NsYWltcyI6IHsiZ2l2ZW5fbmFtZSI6ICJbXCJiNlRram9mV1NSOVVFdy01S2
pVTWhBXCIsIFwiSm9oblwiXSIsICJmYW1pbHlfbmFtZSI6ICJbXCJleXdqMEtjWWNkTjQ3
U0pOcDNqYmZBXCIsIFwiRG9lXCJdIiwgImFkZHJlc3MiOiAiW1wic1J3c09TdW56Tm92RU
xIUXpIdWhFd1wiLCB7XCJzdHJlZXRfYWRkcmVzc1wiOiBcIjEyMyBNYWluIFN0XCIsIFwi
bG9jYWxpdHlcIjogXCJBbnl0b3duXCIsIFwicmVnaW9uXCI6IFwiQW55c3RhdGVcIiwgXC
Jjb3VudHJ5XCI6IFwiVVNcIn1dIn19.kdQyTd-XdPuqkzKCtf0S-jXvK6sbVG8m023QqBS
IuZTNiu8X0OVaONZ9Fs8NuCmGtlOj-ej_BLR1GEZn5x-47eNi5S9vQFOCwoqIxbvV4Puf7
J10htkKWOpo2xhNGG2oeDrOjF8dcrO_4jDfKqiiUeePnCO8Mkscj0cxjlzNSRtojceWKAq
pZnh6rbMqZQkymBNaLd2iiq5IcPrKTrJBW7olhm6gFDSHFOCxVTINLUvKUi3ITeUzCpB3b
R65H4s-56zv2xe4aayve9CjtXXi2Gy2W3nxAsuIQjAJPD_KAOQnhLGotdbuvLMnwPQMwin
39Wj_3mdWfOlu2N8rMbpK_Q
```

(Line breaks for presentation only.)

## SD-JWT Release Format

The following shows the contents of a release document:

{#example-release-payload}
```json
{
    "nonce": "EHobieYMZqLPYDfFJ5dJAA",
    "aud": "https://example.com/verifier",
    "sd_claims": {
        "given_name": "[\"b6TkjofWSR9UEw-5KjUMhA\", \"John\"]",
        "family_name": "[\"eywj0KcYcdN47SJNp3jbfA\", \"Doe\"]",
        "address": "[\"sRwsOSunzNovELHQzHuhEw\", {\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}]"
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
eyJhbGciOiAiUlMyNTYifQ.eyJub25jZSI6ICJFSG9iaWVZTVpxTFBZRGZGSjVkSkFBIiw
gImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgInNkX2NsYWltcyI6I
HsiZ2l2ZW5fbmFtZSI6ICJbXCJiNlRram9mV1NSOVVFdy01S2pVTWhBXCIsIFwiSm9oblw
iXSIsICJmYW1pbHlfbmFtZSI6ICJbXCJleXdqMEtjWWNkTjQ3U0pOcDNqYmZBXCIsIFwiR
G9lXCJdIiwgImFkZHJlc3MiOiAiW1wic1J3c09TdW56Tm92RUxIUXpIdWhFd1wiLCB7XCJ
zdHJlZXRfYWRkcmVzc1wiOiBcIjEyMyBNYWluIFN0XCIsIFwibG9jYWxpdHlcIjogXCJBb
nl0b3duXCIsIFwicmVnaW9uXCI6IFwiQW55c3RhdGVcIiwgXCJjb3VudHJ5XCI6IFwiVVN
cIn1dIn19.kdQyTd-XdPuqkzKCtf0S-jXvK6sbVG8m023QqBSIuZTNiu8X0OVaONZ9Fs8N
uCmGtlOj-ej_BLR1GEZn5x-47eNi5S9vQFOCwoqIxbvV4Puf7J10htkKWOpo2xhNGG2oeD
rOjF8dcrO_4jDfKqiiUeePnCO8Mkscj0cxjlzNSRtojceWKAqpZnh6rbMqZQkymBNaLd2i
iq5IcPrKTrJBW7olhm6gFDSHFOCxVTINLUvKUi3ITeUzCpB3bR65H4s-56zv2xe4aayve9
CjtXXi2Gy2W3nxAsuIQjAJPD_KAOQnhLGotdbuvLMnwPQMwin39Wj_3mdWfOlu2N8rMbpK
_Q
```

(Line breaks for presentation only.)
## Presentation Format

The SD-JWT and the SD-JWT Release can be combined into one document using `.` as a separator:

{#example-release-combined}
```
eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXI
iLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInNHVVc4cl9laXQzYVNxcHFFa
lNDR3dHTExrWjFmVmxONWZNZGZSUlZjb2hyazQwOTRjZXpOSXFxQVlLZjRvRlVWNXVUOUc
tQ3NrMjhIU3lNS2pZUVpaUVRRV2lDOUZhelQxbG85dC1VMU1vUlEzRFZKOFdPeWVoOW5hT
EZvMmdIb2pJbG5ueXpjc1VhdDVCUk8xZUpzb2U2MWdMR3huSTAxYnhhVmlZX2JhRFhvYkN
HaEZPT2NEMTAtbllLNktxeFlQbHdWYm4weUEyOHQxekp1eFVyMENORlM0VmRWMUV1QmpHQ
XUzdFpkdlVEdkozeFEtSVhJMWFjVE5LUzEwVzd5SV9qWGs5TWZDdFdYYXpydkxhLXZwdDd
Sc18tanZCQ3BnNk92cmlFbTg2SWhaR25lV0Y1RUltWVhrQ2tJV2lsSmhOSjdKelhwdDdta
2M0T0ZxM2JwdyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiOiA
xNTE2MjQ3MDIyLCAic2RfY2xhaW1zIjogeyJzdWIiOiAieWxfUDd3WGFzbW5jdzVNczlsZ
3VBam5QMTM2YlNjenplOTkwWVdTTjd4OCIsICJnaXZlbl9uYW1lIjogImZYaGZsV0R1MEZ
oanBUSHlCMXU5ZV9tVERTdEdDLUMzUVp5cy1qbUZQUnMiLCAiZmFtaWx5X25hbWUiOiAiN
DZFdk9jZ0VDdGIwWjV5SGd2dDAwYl9BNWppSXNud2lkOGNOWm5Fbk5FcyIsICJlbWFpbCI
6ICJDeWpzd1JUQ3pnekVZeEl1dXk0SW93MldJb18tZUEzN2J0XzRvOFNxM2s4IiwgInBob
25lX251bWJlciI6ICJ3RmNFUzJWby1xZXdocHpzaTlSNHYwQmljdFJVdVh4NGN0ZTVib19
PMEtZIiwgImFkZHJlc3MiOiAiM2FNbm0yTVl3dUZJc25lLVJhdnpLb29OdW9VcTdfSzRkd
kdmc0dLNXZMUSIsICJiaXJ0aGRhdGUiOiAiWTlMQi1VcDhaT0swbExXTldxY3ZQUXhvakk
1QmhUNmVLX3B5WmxFWVF5TSJ9fQ.qbhmSxY0KTnW4J6tdLRZeKucgc3srozxzyKTwFK199
VmrQfRZ2NXbt9yyg0we44mxv_4o7O7TvH9fsy9CZ1OcNDVDjHEZi0JcixtST0z_KsU1AHp
ODqy0TyCcMUDFcb43nSQ-Or8EX5HdiFjmu1nn8sr24HwpCAQHO8MRDdtoXYx-sgWysIE_q
qagyveoZxuB7bl-rLbFgusJNTE2NZr5cUso57_Zg6lQrxcysuZInwYkxa2SCUY56tFX3xJ
_zYdZx3H4MkLMMlFc2f6z37Pl6zUZFSj7LakWBdq9-eevcw-dGhzEPeETl6ltofJ5NZaDL
HJ8ooIL5z4cmRrd4KBKg.eyJhbGciOiAiUlMyNTYifQ.eyJub25jZSI6ICJFSG9iaWVZTV
pxTFBZRGZGSjVkSkFBIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVy
IiwgInNkX2NsYWltcyI6IHsiZ2l2ZW5fbmFtZSI6ICJbXCJiNlRram9mV1NSOVVFdy01S2
pVTWhBXCIsIFwiSm9oblwiXSIsICJmYW1pbHlfbmFtZSI6ICJbXCJleXdqMEtjWWNkTjQ3
U0pOcDNqYmZBXCIsIFwiRG9lXCJdIiwgImFkZHJlc3MiOiAiW1wic1J3c09TdW56Tm92RU
xIUXpIdWhFd1wiLCB7XCJzdHJlZXRfYWRkcmVzc1wiOiBcIjEyMyBNYWluIFN0XCIsIFwi
bG9jYWxpdHlcIjogXCJBbnl0b3duXCIsIFwicmVnaW9uXCI6IFwiQW55c3RhdGVcIiwgXC
Jjb3VudHJ5XCI6IFwiVVNcIn1dIn19.kdQyTd-XdPuqkzKCtf0S-jXvK6sbVG8m023QqBS
IuZTNiu8X0OVaONZ9Fs8NuCmGtlOj-ej_BLR1GEZn5x-47eNi5S9vQFOCwoqIxbvV4Puf7
J10htkKWOpo2xhNGG2oeDrOjF8dcrO_4jDfKqiiUeePnCO8Mkscj0cxjlzNSRtojceWKAq
pZnh6rbMqZQkymBNaLd2iiq5IcPrKTrJBW7olhm6gFDSHFOCxVTINLUvKUi3ITeUzCpB3b
R65H4s-56zv2xe4aayve9CjtXXi2Gy2W3nxAsuIQjAJPD_KAOQnhLGotdbuvLMnwPQMwin
39Wj_3mdWfOlu2N8rMbpK_Q
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
    2. For each claim that the verifier requires:
       1. Ensure that the claim is present in `sd_claims` both in the SD-JWT and the SD-JWT Release. If `sd_claims` is structured, the claim MUST be present at the same place within the structure.
       2. Check that the BASE64URL encoded hash of the claim value in the SD-JWT Release (which includes the salt and the actual claim value) matches the hash provided in the SD-JWT.
       3. Ensure that the claim value in the SD-JWT Release is a JSON-encoded array of exactly two values.
       4. Store the second of the two values. 
    3. Once all necessary claims have been verified, their values can be
       validated and used according to the requirements of the application.

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


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

This specification uses the terms "access token", "refresh token",
"authorization server", "resource server", "authorization endpoint",
"authorization request", "authorization response", "token endpoint",
"grant type", "access token request", "access token response", and
"client" defined by The OAuth 2.0 Authorization Framework [@!RFC6749].

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

A checks that 

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
RECOMMENDED to base64url encode at least 16 pseudorandom bytes and remove any
trailing `=` characters from the encoded string.

The hashes are built by hashing over string that is formed by JSON-encoding an
array containing the salt and the claim value, e.g.: `["6qMQvRL5haj","Peter"]`.
The hash value is then Base64url encoded and any trailing `=` are removed. Note
that the precise JSON encoding can vary, and therefore, the JSON encodings MUST
be sent to the holder along with the SD-JWT, as described below.

#### Holder Public Key

If the issuer wants to enable holder binding, it includes a public key
associated with the holder, or a reference thereto. 

It is out of the scope of this document to describe how the holder key pair is
established. For example, the issuer MAY create the key pair for the holder or
holder and issuer MAY use pre-established key material.

TODO: What will be the default mechanism in this draft?

#### Other Claims

The SD-JWT payload typically contains other claims, such as `iss`, `iat`, etc. 

### Example

In the following examples, these claims are the payload of the SD-JWT:

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

```json
{
    "iss": "https://example.com/issuer",
    "sub_jwk": {
        "kty": "RSA",
        "n": "mBWK1BtMhWTsMHmxvzrGuvYcbq_5dl8YgjwclkZ-knERWqAyoioHUmNgCfiM4RBBGwh2xW8QKv6n-i5RyYHmY6DGOhOH1nxGR7aet1ULUgoau_A1_JtGJQlO9iJSs1QXE0W9cLzMxZJaC-e-fDFu3c6PHS4dvmsxA0eWNpe_3y1joXdCvzoBECiWXpl9wW3lvwXJddSGhdnvFB3Lj9GFRGgdFVPEelkw4_S8bnn1WBdjAd8AzY7DK4Up6f0_zdUJ0plmrR04WKzhQ7gpS3z6QJ3Gd54lASBXvGn82efAymtdO83RNFs1sRJ6WKYdokn7q0VxaCOe7bYt3JJsmkkTEw",
        "e": "AQAB"
    },
    "iat": 1516239022,
    "exp": 1516247022,
    "sd_claims": {
        "sub": "GkpL7BdF43J2_xLy3J_GRJZC3M5M6xa4mxaGP3sykvs",
        "given_name": "33PnYpkTB6yRY8XEhWKf3tpgf29YvvixOVY8I1nrr3w",
        "family_name": "A0ZEHKs9Yr2rc5uYEjoaiRxPNno_jAa2_UUvHwMrV_Y",
        "email": "GnloszsOs-2p8fHdbToLziZk27eLU9gfhnJni3dPpyY",
        "phone_number": "qKXC47L-VXavDrbdzIgimKDhiMfJjvBDy5ainkwGHlI",
        "address": "74Py7HIMNWg804aoyba5tMvI0NCJJzQvMkfPe4v5AdQ",
        "birthdate": "CxqGCua-9Rl9pvPuMztJwv-7ZzOw3Sje5n8ROgvmjqs"
    }
}
```

The SD-JWT is then signed by the issuer to create a document like the following
(shortened for presentation):

`eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAic3ViX2p3ayI6IHsT(...)DRyTmhCMzkzMWNNPSIsICJhZGRyZXNzIjogIlNxVHhiMU8zSEZnVEdnYkw3d1EyZ3o5akNiUFdWclB0NmZxWE1ZbXhKNPSJ9fQ.cHNaU6b9hvVRNevXlPlmKCr6n-LHgvGcAYwAtBi6YIKPqqfIiBG1L-eo4wPTY-Fo4FYHJ5iJ3InGSxwlWboxwcAZ-cdedhfBmw`

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

```json
{
    "sd_claims": {
        "sub": "[\"d_FsrvwS3RuFvO9W3FG3Nw\", \"6c5c0a49-b589-431d-bae7-219122a9ec2c\"]",
        "given_name": "[\"JwcCSabVqxVpEOCia8Zocg\", \"John\"]",
        "family_name": "[\"5OqO4BR4YpKvOgIjBsc_7A\", \"Doe\"]",
        "email": "[\"-z-w6ronWMPghRPEWCJLEA\", \"johndoe@example.com\"]",
        "phone_number": "[\"gjD0GK8rbe0qTtHW8Xy-Aw\", \"+1-202-555-0101\"]",
        "address": "[\"PI5cp5zjN659nLRfSjkbXw\", {\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}]",
        "birthdate": "[\"6z0iSqcodlh-HkIeTUboQg\", \"1940-01-01\"]"
    },
    "sub_jwk_private": {
        "kty": "RSA",
        "n": "zgHzSGBWdPmWJaWSfdf8MaD0gKBeXWQ47MdWiDM4M5podnU6Mmbm3MDJQyUgY_0KR1JSVWyHpjyMtv4kKeVA2iIwZfSaEJEtlV4r0fRMcq3XhaLEfIUsMjb_gJzL1RpJXth-2sbQBVPzJuKQXlU-iRh5TUdaqelQ-Xt2QOnapAzzYTUUjhqW4BJwaceFxze4DzkUpVVG58i6dJQxRWTJ_KhwCrwywj2t1TFxkOUbhHe8Y-t68kw2fvwFqsHDasMs19MNTcjiEJa99J5vcLUz2p3TMaGHzvmPnC2o03eqjnl4fI7kVrDXyeWLZeaiwv0fzbOVhQlCspfbeXvsJT0DhQ",
        "e": "AQAB",
        "d": "mmSxzVOOWFraIdrmYHRoKVXFCUWnk3zSgPqgqrEgdORLWERhWnbunRHLhQwlK2rwsiVLWYReYcNNfrQXrGKJ6THobfEVKkd0D1clplPem7AYL6qecehpCDVZ5i0dQthRlsjQwexw6R1SxZjVtC1VEfCKsNVCaMdZDbFvHhVl7L4C4QwqmIZBuJiVk0n0J5DtaR-aH0wGFuKtOoBXzgqR6EW6gzrrJLu5nqWCT_z5869x7SmZPVJgDSXxHqQl9PBnMsgkufpEFTwoPekQyGymXLV3EsLzHI36tAFF3XRa_wnt_oVce5MpJSXopoXm8QF5n_p4i58TKTddjhdK6eF2_Q",
        "p": "9wheZIIly70KU4nLhCKMe-bn-lpuQGfNXIDL1uoZbbsLdz-wg-1qUGP8tpEfCSTgA1--NmjOacv2pWLhNG5V5MZgPv29owY0ikkl3rKmHiltrvGrqpz6iSfRVN9J70lqgK5m8jpmilkH1eid38c-zXNWFerOBmXWuHLOyK7Cd6M",
        "q": "1XxXxA1ZPnQ_2COfoYvKlzzaKZ3UnUuXdkFPDoD0ZHinfan9FQE_o2AgHKDoZLW4OiA8WWq8tQCrija-aUwbU5yjuTgJi_u94RRTRQTvbYoOkmu90HsBi-df_iDlltnk3WtpeLeUa1M8PFKe6hGobYVhNj9nL0SoSs1RjW2Qarc",
        "dp": "UjDhnxVCWAg8oFDPetY34Z2Q_1YJKrqetDFSIN5guYarKPDy3OIoJjkuQtwD9HnlYpn_YoD6dG7dUGeWwGgZgfWS3kJ0TwJohr4RsIfGB3EHQla8JBb4sJuj5VYpdkj5-3iLXfqaVVuL5NrxdBwJxDeko8Qs6ioGB_aC4Hhs0Xs",
        "dq": "Ia6wmjoQ7o2g1RUpxm8r05jCQvan6PlYOEwtkPg_luqCYo1DZOEBjWFJL7sjb2BMZL9ZRjJU-6nTZsckW7CqTxLTshFpUDCz0KNIUAdrTzkM-4UMOaxunggvWQUPtDFErrqXtXghbp1_T3UppXyLulvk7o4qVYbblpG2YD39Hxk",
        "qi": "ymxeRT2Miru6riR4otygjbCi0-Z82Ob45U_vCB2JrHRBjEKvK99hgUlYonsC3Q23A0sZJbqCgIuFtVIA43dveSz-KGPl1asZViz6WFFS4BZgGhhlv8y_Rnhfq4MrMdpYbPCLjCSWf8ywhvFBRlia14Tfme6dinTnSWUi70d-1v0",
        "key_size": 2048
    }
}
```

## SD-JWT and SVC Combined Format

For transporting the SVC together with the SD-JWT from the issuer to the holder,
the SVC is base64url encoded (as the parts of any JWT, todo reference) and
appended to the SD-JWT using `.` as the separator:

`eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly3ayI6IHsT(...)DRyTmXhKNPSJ9fQ.cHNaU6b9hAZ-cdedhfBmw.ewogICAgImdpdmVuX25hbWUiOi(...)MTk0MC0wMS0wMVwiXSIKfQ`

(Shortened for presentation.)

## SD-JWT Release Format

The following shows the contents of a release document:
```
{
    "nonce": 882515,
    "sd_claims": {
        "family_name": "[\"wHPRcNJ-62nuGbLRUu08wQ\", \"Doe\"]",
        "address": "[\"ZAHYs4SE5Un9Er-YeUs4Zg\", {\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}]"
    }
}
```
For each claim, an array of the salt and the claim value is contained in the
`sd_claims` object. The SD-JWT Release MAY contain further claims, for example, to
ensure a binding to a concrete transaction (in the example the `nonce` claim).

If holder binding is desired, the SD-JWT Release is signed by the holder. If no
holder binding is to be used, the `none` algorithm is used, i.e., the document
is not signed.

In any case, the result is encoded as described in [@!RFC7515]:

`eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ImQyTmNSd3IzIiwic2QiOnsiZ2l2ZW5fbBsZSJdLCJiaXJ0aGRhdGUiOlsiaEdKZjN2UTJsZk8iLCIyMDAwLTAxLTAxIl19fQ.Dt99fCFmXYLXRLwk4Y4DrAOaY5ufoYvMijtJACDzoB0`

## Presentation Format

The SD-JWT and the SD-JWT Release can be combined into one document using `.` as a separator:

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIic0PSJ9fQ.qWVAIJ4OzoIUEy-9v0af3UW7NKufBh34V6JRBe7I8H0.eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ImQyTmNSd3IzIiwic2QiOnsiZ2l2ZW5fbBsZSJdLCJiaXJ0aGRhdGUiOlsiaEdKZjN2UTJsZk8iLCIyMDAwLTAxLTAxIl19fQ.Dt99fCFmXYLXRLwk4Y4DrAOaY5ufoYvMijtJACDzoB0`

# Verification

TODO!

# Security Considerations {#security_considerations}

For the security of this scheme, the following properties are required of the hash function:

- Given a claim value, a salt, and the resulting hash, it is hard to find a second salt value so that HASH(salt | claim_value) equals the hash.


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


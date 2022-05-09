%%%
title = "Selective Disclosure JWS (SD-JWS)"
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
    email = "Kristina.Yasuda%40microsoft.com"

[[author]]
initials="M."
surname="Jones"
fullname="Michael Jones"
organization="Microsoft"
    [author.address]
    email = "mbj@microsoft.com"
    uri = "https://self-issued.info/"
        
    
%%%

.# Abstract 

This document specifies conventions for creating JSON Web Signature (JWS)
documents that support selective disclosure of claim values. 

{mainmatter}

# Introduction {#Introduction}

The JSON-based content of JSON Web Signatures (JWS) as defined in [@!RFC7515] is
secured against modification using digital signatures. A consumer of a JWS
document that has checked the document's signature can safely assume that the
contents of the document have not been modified.  However, anyone receiving a
JWS document can read all contents of the document. 

For example, a common use case is that the signed document represents a user's
identity credential, created by an issuer. The issuer includes the user's public
key or a reference thereto. To proof their identity to a verifier, the user can
then send the issuer-signed credential plus a signature over some
transaction-specific values, the so-called proof. It is signed using the user's
private key. This demonstrates possession of the private key, and by extension,
the identity of the user. 

The problem is, that using this approach, the user has to release the full
issuer-signed credential to the verifier. The credential is often created once
and can then be used for many transactions. Thus, it is in the user's interest
that the credential creates many user attributes which can be disclosed
selectively to verifiers.

This document describes a format for JWS documents that support selective
disclosure (SD-JWS) including a format for proofs.

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

 * A **JWS-SD** is a signed JWT [@!RFC7515], i.e., a JWS, that is formatted
   according to the rules defined below and therefore supports selective
   disclosure. 
 * An **issuer** is the entity that creates a JWS-SD.
 * A **holder** has control over a JWS-SD and the private key for the public key
   contained in the JWS-SD.
 * A **verifier** checks, upon receiving a JWS-SD and a matching proof from a
   holder, that the JWS-SD was issued for the holder and can extract claims from
   the JWS-SD as far as their values have been released by the holder.  

# Working Principle

In the following, the working principle of JWS-SDs and matching proofs is described on a conceptual level.

## Creating a JWS-SD

A JWS-SD, at its core, is a signed document containing some metadata, the
holder's public key, and hashed and salted claims. It is signed using the
issuer's private key.

```
    JWS-SD-DOC = (METADATA, HOLDER-PUBLIC-KEY, HS-CLAIMS)
    JWS-SD = JWS-SD-DOC | SIG(JWS-SD-DOC, ISSUER-PRIV-KEY)
```

`HS-CLAIMS` is usually a simple object with claim names mapped to  salted and
hashed claim values:
```
    HS-CLAIMS = (
        CLAIM-NAME: HASH(SALT | CLAIM-VALUE)
    )*
```

`HS-CLAIMS` can also be nested deeper to capture more complex objects, as will be shown later.

## Creating a Proof

For a proof, a holder releases a document such as the following to the verifier:

```
    PROOF-DOC = (METADATA, SALTS)
    PROOF = PROOF-DOC | SIG(PROOF-DOC, HOLDER-PRIV-KEY)
```

`SALTS` is usually a simple object with claim names mapped to values and salts:

```
    SALTS = (
        CLAIM-NAME: (DISCLOSED-SALT, DISCLOSED-VALUE)
    )
```

Just as `HS-CLAIMS`, `SALTS` can be more complex as well.

## Verifying 

A verifier first checks that the `PROOF` was indeed signed by the private key
belonging to the public key contained in `JWS-SD-DOC`. The verifier can then
check that for each claim in `PROOF`, the hash `HASH(DISCLOSED-SALT |
DISCLOSED-VALUE)` matches the hash under the given claim name in the JWS-SD.

# JWS-SD Format

TODO: The holder needs to be able to figure out what the correct raw value was.
TODO: The holder needs to learn the salts.

A JWS-SD is a JWT signed using the issuer's private key. The following shows an example for a JWS-SD document:

```
{
    "iss": "https://example.com",
    "sub_jwk": {
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\n    VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W\n    -5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQ\n    MicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdk\n    t-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-cs\n    FCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB"
    },
    "nbf": "1541493724",
    "iat": "1541493724",
    "exp": "1573029723",
    "sd_claims": {
        "given_name": "6nLHlZQpbkW4wqKWZE2YhYH1jPrGYB0SLtCovXwC6L8=",  // not actually the correct values
        "family_name": "EpdMWYlm3X/8hyPfAFoI/14D9ohtzHMJcA53S3K6GrQ=",
        "birthdate": "WAmS827uHRF1xhKGAJVft5iyF9LW3vQ2lfOB7r96Yg4="
    }
}
```
In `sd_claims`, the hashes are built by hashing a JSON array containing the salt
and the claim value, where there must be no white space characters in the JSON
notation: `["6qMQvRL5haj","Peter"]`. The hashes are Base64 encoded.

TODO: Consider using Base85 instead.

The JWS-SD is then signed by the issuer, to create a document like the following (shortened for presentation):

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIic0PSJ9fQ.qWVAIJ4OzoIUEy-9v0af3UW7NKufBh34V6JRBe7I8H0`

# JWS-SD Proof Format

The following shows the contents of a proof document:
```
{
    "nonce": "d2NcRwr3",
    "sd": {
        "given_name": ["6qMQvRL5haj", "Peter"],
        "family_name": ["HMJcA53S3K6", "Example"],
        "birthdate": ["hGJf3vQ2lfO", "2000-01-01"],
    }
}
```
For each claim, an array of the salt and the claim value is contained in the `sd` object.

The JWS-SD Proof is then signed by the holder, to create a document like the following:

`eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ImQyTmNSd3IzIiwic2QiOnsiZ2l2ZW5fbBsZSJdLCJiaXJ0aGRhdGUiOlsiaEdKZjN2UTJsZk8iLCIyMDAwLTAxLTAxIl19fQ.Dt99fCFmXYLXRLwk4Y4DrAOaY5ufoYvMijtJACDzoB0`

# Presentation

The JWS-SD and the JWS-SD Proof can be combined into one document using `.` as a separator:


`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIic0PSJ9fQ.qWVAIJ4OzoIUEy-9v0af3UW7NKufBh34V6JRBe7I8H0.eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ImQyTmNSd3IzIiwic2QiOnsiZ2l2ZW5fbBsZSJdLCJiaXJ0aGRhdGUiOlsiaEdKZjN2UTJsZk8iLCIyMDAwLTAxLTAxIl19fQ.Dt99fCFmXYLXRLwk4Y4DrAOaY5ufoYvMijtJACDzoB0`


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

   *  first draft
   


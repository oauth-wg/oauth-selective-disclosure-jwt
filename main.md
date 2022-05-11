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
    email = "Kristina.Yasuda@microsoft.com"

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
documents that support selective disclosure of JWT claim values. 

{mainmatter}

# Introduction {#Introduction}

The JSON-based content of JSON Web Signatures (JWS) as defined in [@!RFC7515] is
secured against modification using digital signatures. A consumer of a JWS
document that has checked the document's signature can safely assume that the
contents of the document have not been modified.  This means that anyone 
receiving a JWS document can read all contents of the document because the all 
of the JWT claims are secured using one signature.

This is not a problem in a federated identity use case when the user has given 
the Client authorization to access certain resources, and the Authorization 
Server returns to the Client only the claims the user has consented to release.

However, in a use case involving verifiable credentials where the user is 
presenting a JWS signed by the issuer at multiple Clients over a period of time
in multiple transactions, the user's ability to choose which claims within 
a JWS to present to a certain Client becomes critical. 

This document describes a format for JWS documents that enable selective disclosure
of the included claims (SD-JWS), including a format for proofs, which are digitally
signed JWS documents presented during verification.

In a common use case, such JWS document includes claims describing natural persons, 
the mechanisms defined in this document can be used for any other use cases as well.

It is important to note that this format enables selective disclosure of claims, but
in itself it does not achieve unlinkability of the subject of a JWS document.

Note: discuss how much we want to get into the holder binding (user's public key contained inside an SD-JWS).
From my perspective, it is very use case specific and orthogonal to the general mechanism of selective disclosure
we are trying to define here.

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

 * An **SD-JWS** is a signed JWT [@!RFC7515], i.e., a JWS, that is formatted
   according to the rules defined below and therefore supports selective
   disclosure. 
 * An **issuer** is the entity that creates a digital signature on an SD-JWS.
 * A **wallet** is the entity that receives, stores, presents, and manages SD-JWSs
   enabling the user to exercise control over SD-JWSs.
 * A **verifier** checks, upon receiving a SD-JWS and a matching proof from a
   holder, that the SD-JWS was issued for the holder and can extract claims from
   the SD-JWS as far as their values have been released by the holder.
 * A **proof** 

Note: discuss if we want to include Client, Authorization Server for the purpose of
ensuring continuity and separating the entity from the actor.

Note: discuss definition of `proof`.

Note: holder of wallet? add that wallet can be of any deployment

# Concept

In the following section, the concept of SD-JWSs and matching proofs are described at a conceptual level.

## Creating a SD-JWS

An SD-JWS, at its core, is a digitally signed document containing hashes over the claim values and unique salts,
the holder's public key and other metadata. It is digitally signed using the issuer's private key.

```
    SD-JWS-DOC = (METADATA, HOLDER-PUBLIC-KEY, HS-CLAIMS)
    SD-JWS = SD-JWS-DOC | SIG(SD-JWS-DOC, ISSUER-PRIV-KEY)
```

`HS-CLAIMS` is usually a simple object with claim names mapped to hashes over the claim values with unique salts:
```
    HS-CLAIMS = (
        CLAIM-NAME: HASH(SALT | CLAIM-VALUE)
    )*
```

`HS-CLAIMS` can also be nested deeper to capture more complex objects, as will be shown later.

## Creating a Proof

For a proof, a holder releases a JWS document with the claim values that the user has consented to release
such as the following to the verifier:

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

Note: Suggest we separate creating a SD-JWS from creating a proof. those happen at a different period of time.
And the way it is written now, that is not exactly clear. I would make it 
Creating a SD-JWS -> SD-JWS Salt/Value Container -> Creating a Proof -> Verifying (SD-JWS Format, SD-JWS Proof Format)

## Verifying 

A verifier first checks that the `PROOF` was indeed signed by the private key
belonging to the public key contained in `SD-JWS-DOC`. 

The verifier can then check that for each claim in `PROOF`, the hash `HASH(DISCLOSED-SALT |
DISCLOSED-VALUE)` matches the hash under the given claim name in the SD-JWS.

# SD-JWS Format

A SD-JWS is signed using the issuer's private key. The following shows an example for a body of a SD-JWS document:

```
{
    "iss": "https://example.com/issuer",
    "sub_jwk": {
        "kty": "RSA",
        "n": "rCZ-u2jj0CCRswyA-GtRyKMqRe4c-gjOjZDNaMcIJg8vSYDV7XHExeex3uqQBfOyV2_ukCZRc2gYCr2OzyqkqtQe_vQjL66uA3xktxNMTeqtYfqKeosfZ0cvc90bZf_GPnY-lV1GFrddG0jQ_Xg4ygitC7NAeQLMCuT4HPVUNgfR0FIC5zZ_z-0qXHT46Tco48Obp-k9dEfdyIKFpLjEF13AoFzfohaA_IqJCuNGCoGvvgoEMwPSAe-r9V11MhiMnDXNeIXB0zsEPyO2ve9c_hcpfi53c9JSBaQFSeV707prScdh9IWb9Yks6a2sNC83ZYYskUeWYRqNFFf9xiq1XQ",
        "e": "AQAB"
    },
    "iat": 1516239022,
    "exp": 1516247022,
    "sd_claims": {
        "given_name": "DumhwVNX7ljM2kbW9S0nISOVRBCgBGCAqYUgiB3RoFQ",
        "family_name": "XW2uJY_3ewKOzdCvXFx3n0GR1e7AFFITlRs9LaEpXhc",
        "email": "lN7aE0WeDBQ7HZuWCNYSljPR8nussvZHoDinaAnZyZ4",
        "phone_number": "BkhM0_2EX9DxckOS_KCOGpQ4NawNFozGJbMrUWWQgow",
        "address": "4axMBso9yntfx2lAsYOf1FUDovROgeKRpq3PcBExK9M",
        "birthdate": "o5iE3bwryuMLLh9ZB1IYtbWZ2eNcFABNKNWqIyW3esw"
    }
}
```
In `sd_claims`, the hashes are built by hashing over a JSON array containing the
salt and the claim value, in the JSON notation: `["6qMQvRL5haj","Peter"]`. The
salt values and the hashes are Base64url encoded, trailing `=` removed. Note
that the precise JSON encoding can vary, and therefore, the JSON encodings are
sent to the holder along with the SD-JWS, as described below.

TODO: Consider using Base85 instead.

The SD-JWS is then signed by the issuer, to create a document like the following (abbreviated for for display purposes only):

`eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAic3ViX2p3ayI6IHsT(...)DRyTmhCMzkzMWNNPSIsICJhZGRyZXNzIjogIlNxVHhiMU8zSEZnVEdnYkw3d1EyZ3o5akNiUFdWclB0NmZxWE1ZbXhKNPSJ9fQ.cHNaU6b9hvVRNevXlPlmKCr6n-LHgvGcAYwAtBi6YIKPqqfIiBG1L-eo4wPTY-Fo4FYHJ5iJ3InGSxwlWboxwcAZ-cdedhfBmw`

Note: need to define `sub_jwk`. Why are we using `sub_jwk`?

# SD-JWS Salt/Value Container

Besides the SD-JWS itself, the holder needs to learn the raw claim values that
are contained in the SD-JWS, along with the precise input to the hash
calculation, and the salts.

The issuer therefore creates a Salt/Value Container (SVC) as follows:

```
{
    "given_name": "[\"J8Lxj906DiXX_aE4zs05cg\", \"John\"]",
    "family_name": "[\"wHPRcNJ-62nuGbLRUu08wQ\", \"Doe\"]",
    "email": "[\"Iyby9C7l19MhWXC7z2aDFA\", \"johndoe@example.com\"]",
    "phone_number": "[\"o1s_VI5qyyu29YqQrMI5OA\", \"+1-202-555-0101\"]",
    "address": "[\"ZAHYs4SE5Un9Er-YeUs4Zg\", {\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}]",
    "birthdate": "[\"RH0rt8U8LpC9elOus2y5Tg\", \"1940-01-01\"]"
}
```

For transporting the SVC together with the SD-JWS from the issuer to the holder,
the SVC is base64url encoded (as the parts of any JWS, todo reference) and
appended to the SD-JWS using `;` as the separator (abbreviated for for display purposes only):

`eyJhbGciOiAiUlMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly3ayI6IHsT(...)DRyTmXhKNPSJ9fQ.cHNaU6b9hAZ-cdedhfBmw;ewogICAgImdpdmVuX25hbWUiOi(...)MTk0MC0wMS0wMVwiXSIKfQ`

# SD-JWS Proof Format

The following shows the contents of a proof document:
```
{
    "nonce": 882515,
    "sd": {
        "family_name": "[\"wHPRcNJ-62nuGbLRUu08wQ\", \"Doe\"]",
        "address": "[\"ZAHYs4SE5Un9Er-YeUs4Zg\", {\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}]"
    }
}
```
For each claim, an array of the salt and the claim value is contained in the `sd` object.

The SD-JWS Proof is then signed by the holder, to create a document like the following:

`eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6ImQyTmNSd3IzIiwic2QiOnsiZ2l2ZW5fbBsZSJdLCJiaXJ0aGRhdGUiOlsiaEdKZjN2UTJsZk8iLCIyMDAwLTAxLTAxIl19fQ.Dt99fCFmXYLXRLwk4Y4DrAOaY5ufoYvMijtJACDzoB0`

# Presentation

The SD-JWS and the SD-JWS Proof can be combined into one document using `;` as a separator:


`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIic0PSJ9fQ.qWVAIJ4OzoIUEy-9v0af3UW7NKufBh34V6JRBe7I8H0.eyJhbGciOiJIUzI1NiJ9;eyJub25jZSI6ImQyTmNSd3IzIiwic2QiOnsiZ2l2ZW5fbBsZSJdLCJiaXJ0aGRhdGUiOlsiaEdKZjN2UTJsZk8iLCIyMDAwLTAxLTAxIl19fQ.Dt99fCFmXYLXRLwk4Y4DrAOaY5ufoYvMijtJACDzoB0`


# Security Considerations {#security_considerations}

For the security of this scheme, the following properties are required of the hash function:

- Given a claim value, a salt, and the resulting hash, it is hard to find a second salt value so that HASH(salt | claim_value) equals the hash.

Add: The Salts must be random/long enough so that the attacker cannot brute force them.

Note: No need for the wallet-generated hashes? to prevent issuer-verifier collusion

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
   


%%%
title = "Selective Disclosure JWT (SD-JWT)"
abbrev = "SD-JWT"
ipr = "trust200902"
area = "Security"
workgroup = "Web Authorization Protocol"
keyword = ["security", "oauth2"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-fett-oauth-selective-disclosure-jwt-02"
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

The JSON-based claims in a signed JSON Web Token (JWT) [@!RFC7519] document are
secured against modification using JSON Web Signature (JWS) [@!RFC7515] digital
signatures. A consumer of a signed JWT document that has checked the document's
signature can safely assume that the contents of the document have not been
modified.  However, anyone receiving an unencrypted JWT can read all of the
claims and likewise, anyone with the decryption key receiving an encrypted JWT
can also read all of the claims.

This document describes a format for signed JWTs that supports selective
disclosure (SD-JWT), enabling sharing only a subset of the claims included in
the original signed JWT instead of releasing all the claims to every verifier.
During issuance, an SD-JWT is sent from the issuer to the holder alongside an
SD-JWT Salt/Value Container (SVC), a JSON object that contains the mapping
between raw claim values contained in the SD-JWT and the salts for each claim
value. 

This document also defines a format for SD-JWT Releases (SD-JWT-R), which convey
a subset of the claim values of an SD-JWT to the verifier. For presentation, the
holder creates an SD-JWT-R and sends it together with the SD-JWT to the
verifier. To verify claim values received in SD-JWT-R, the verifier uses the
salts values in the SD-JWT-R to compute the hash digests of the claim values and
compare them to the ones in the SD-JWT.

One of the common use cases of a signed JWT is representing a user's identity
created by an issuer. As long as the signed JWT is one-time use, it typically
only contains those claims the user has consented to release to a specific
verifier. However, when a signed JWT is intended to be multi-use, it needs to
contain the superset of all claims the user might want to release to verifiers
at some point. The ability to selectively disclose a subset of these claims
depending on the verifier becomes crucial to ensure minimum disclosure and
prevent verifiers from obtaining claims irrelevant for the transaction at hand.

One example of such a multi-use JWT is a verifiable credential, a
tamper-evident credential with a cryptographically verifiable authorship that
contains claims about a subject. SD-JWTs defined in this document enable such
selective disclosure of claims. 

While JWTs for claims describing natural persons are a common use case, the
mechanisms defined in this document can be used for many other use cases as
well.

This document also describes holder binding, or the concept of binding SD-JWT to
key material controlled by the subject of SD-JWT. Holder binding is optional to
implement.


## Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they
appear in all capitals, as shown here.

**base64url** denotes the URL-safe base64 encoding without padding defined in
Section 2 of [@!RFC7515].

# Terms and Definitions

Selective Disclosure JWT (SD-JWT) 
:  A JWT [@!RFC7515] created by the issuer, which is signed as a JWS [@!RFC7515], 
   that supports selective disclosure as defined in this document.

SD-JWT Salt/Value Container (SVC) 
:  A JSON object created by the issuer that contains mapping between 
   raw claim values contained in the SD-JWT and the salts for each claim value.

SD-JWT Release (SD-JWT-R) 
:  A JWT created by the holder that contains a subset of the claim values of an SD-JWT in a verifiable way. 

Holder binding 
:  Ability of the holder to prove legitimate possession of SD-JWT by proving 
   control over the same private key during the issuance and presentation. SD-JWT signed by the issuer contains
   a public key or a reference to a public key that matches to the private key controlled by the holder.

Claim name blinding
:  Method to extend selective disclosure to claim names by hiding not only a claim's value
   but also the claim name from verifiers to which the claim was not disclosed.

Issuer 
:  An entity that creates SD-JWTs (2.1).

Holder 
:  An entity that received SD-JWTs (2.1) from the issuer and has control over them.

Verifier 
:  An entity that requests, checks and extracts the claims from SD-JWT-R (2.2)

Note: discuss if we want to include Client, Authorization Server for the purpose of
ensuring continuity and separating the entity from the actor.

# Flow Diagram

~~~ ascii-art
           +------------+
           |            |
           |   Issuer   |
           |            |
           +------------+
                 |
               Issues
           SD-JWT and SVC
                 |
                 v
           +------------+
           |            |
           |   Holder   |
           |            |
           +------------+
                 |
              Presents
         SD-JWT-R and SD-JWT
                 |
                 v
           +-------------+
           |             |+
           |  Verifiers  ||+
           |             |||
           +-------------+||
            +-------------+|
             +-------------+
~~~
Figure: SD-JWT Issuance and Presentation Flow

# Concepts

In the following, the contents of SD-JWTs and SD-JWT Releases are described at a
conceptual level, abstracting from the data formats described afterwards.

## Creating an SD-JWT

An SD-JWT, at its core, is a digitally signed document containing hash digests over the claim values with unique random salts and other metadata. 
It MUST be digitally signed using the issuer's private key.

```
SD-JWT-DOC = (METADATA, SD-CLAIMS)
SD-JWT = SD-JWT-DOC | SIG(SD-JWT-DOC, ISSUER-PRIV-KEY)
```

`SD-CLAIMS` can be a simple object with claim names mapped to hash digests over the claim values with unique random salts:
```
SD-CLAIMS = (
    CLAIM-NAME: HASH(SALT | CLAIM-VALUE)
)*
```

The claim name (`CLAIM-NAME`) is an optional 

`SD-CLAIMS` can also be nested deeper to capture more complex objects, as will be shown later.

`SD-JWT` is sent from the issuer to the holder, together with the mapping of the plain-text claim values, the salt values, and potentially some other information. 

## Creating an SD-JWT Release

To disclose to a verifier a subset of the SD-JWT claim values, a holder creates a JWT such as the
following:

```
SD-JWT-RELEASE-DOC = (METADATA, SD-RELEASES)
SD-JWT-RELEASE = SD-JWT-RELEASE-DOC
```


`SD-RELEASES` follows the structure of `SD-CLAIMS` and can be a simple object with claim names mapped to values and salts:

```
SD-RELEASES = (
    CLAIM-NAME: (DISCLOSED-SALT, DISCLOSED-VALUE)
)
```

Just as `SD-CLAIMS`, `SD-RELEASES` can be more complex as well.

`SD-JWT-RELEASE` is sent together with `SD-JWT` from the holder to the
verifier.

## Optional Holder Binding

Some use-cases may require holder binding. 

If holder binding is desired, `SD-JWT` must contain information about key material controlled by the holder:

```
SD-JWT-DOC = (METADATA, HOLDER-PUBLIC-KEY, SD-CLAIMS)
```

Note: How the public key is included in SD-JWT is out of scope of this document. It can be passed by value or by reference.

With holder binding, the `SD-JWT-RELEASE` is signed by the holder using its private key. It therefore looks as follows:

```
SD-JWT-RELEASE = SD-JWT-RELEASE-DOC | SIG(SD-JWT-RELEASE-DOC, HOLDER-PRIV-KEY)
```

## Optional Claim Name Blinding

If claim name blinding is used, `SD-CLAIMS` is created as follows:
```
SD-CLAIMS = (
    CLAIM-NAME-PLACEHOLDER: HASH(SALT | CLAIM-VALUE | CLAIM-NAME)
)*
```

`CLAIM-NAME-PLACEHOLDER` is a placeholder used instead of the original claim
name, chosen such that it does not leak information about the claim name (e.g.,
randomly).

The contents of `SD-RELEASES` are modified as follows:
```
SD-RELEASES = (
    CLAIM-NAME-PLACEHOLDER: (DISCLOSED-SALT, DISCLOSED-VALUE, DISCLOSED-CLAIM-NAME)
)
```
Note that blinded and unblinded claim names can be mixed in `SD-CLAIMS` and accordingly in `SD-RELEASES`.

## Verifying an SD-JWT Release

A verifier checks that 

 * for each claim in `SD-JWT-RELEASE`, the hash digest over the disclosed values
   matches the hash digest under the given claim name in `SD-JWT`,
 * if holder binding is used, the `SD-JWT-RELEASE` was signed by the private key
 belonging to `HOLDER-PUBLIC-KEY`.

The detailed algorithm is described below.

# Data Formats

This section defines data formats for SD-JWTs (containing hash digests of the salted
claim values), SD-JWT Salt/Value Containers (containing the mapping of the
plain-text claim values and the salt values), and SD-JWT Releases (containing a
subset of the same mapping).

## Format of an SD-JWT

An SD-JWT is a JWT that MUST be signed using the issuer's private key. The
payload of an SD-JWT MUST contain the `sd_digests` and `sd_hash_alg` claims
described in the following, and MAY contain a holder's public key or a reference
thereto, as well as further claims such as `iss`, `iat`, etc. as defined or
required by the application using SD-JWTs.

### `sd_digests` Claim (Digests of Selectively Disclosable Claims)

An SD-JWT MUST include hash digests of the salted claim values that are included by the issuer
under the property `sd_digests`. 

The issuer MUST choose a unique and cryptographically random salt value
for each claim value. Each salt value
SHOULD contain at least 128 bits of pseudorandom data, making it hard for an
attacker to guess. The salt value MUST then be encoded as a string. It is
RECOMMENDED to base64url-encode the salt value.

The issuer MUST build the digests by hashing over a JSON literal according to
[@!RFC8259] that is formed by
JSON-encoding an object with the following contents:

 * REQUIRED with the key `s`: the salt value,
 * REQUIRED with the key `v`: the claim value (either a string or a more complex object, e.g., for the [@OIDC] `address` claim),
 * OPTIONAL, with the key `n`: the claim name (if claim name blinding is to be used for this claim).

The following is an example for a JSON literal without claim name blinding:

```
{"s": "6qMQvRL5haj", "v": "Peter"}
```

The following is an example for a JSON literal with claim name blinding:

```
{"s": "6qMQvRL5haj", "v": "Peter", "n": "given_name"}
```

IMPORTANT: JSON encoding according to [@!RFC8259] allows for white space
characters and other variations in the encoded representation. To ensure that
issuer and verifier produce the same hash digest, the issuer therefore sends the
JSON literal to the holder along with the SD-JWT, as described below.

The `sd_digests` claim contains an object where claim names are mapped to the
respective digests. If a claim name is to be blinded, the digests MUST contain
the `n` key as described above and the claim name in `sd_digests` MUST be
replaced by a placeholder value that does not leak information about the claim's original name. The same placeholder value is to be used in the SVC and SD-JWT-R described below.


#### Flat and Structured `sd_digests` objects

The `sd_digests` object can be a 'flat' object, directly containing all claim
names and hashed claim values without any deeper structure. The `sd_digests`
object can also be a 'structured' object, where some claims and their respective
hash digests are contained in places deeper in the structure. It is at the issuer's
discretion whether to use a 'flat' or 'structured' `sd_digests` SD-JWT object,
and how to structure it such that it is suitable for the use case. 

Example 1 below is a non-normative example of an SD-JWT using a 'flat'
`sd_digests` object and Example 2 in the appendix shows a non-normative example
of an SD-JWT using a 'structured' `sd_digests` object. The difference between
the examples is how the `address` claim is disclosed.

Appendix 2 shows a more complex example using claims from eKYC (todo:
reference).

### Hash Function Claim

The claim `sd_hash_alg` indicates the hash algorithm used by the Issuer to generate
the hashes of the salted claim values. The hash algorithm identifier MUST be a
value from the "Hash Name String" column in the IANA "Named Information Hash
Algorithm" registry [IANA.Hash.Algorithms]. SD-JWTs with hash algorithm
identifiers not found in this registry are not considered valid and MUST NOT be
accepted by verifiers.

### Holder Public Key Claim

If the issuer wants to enable holder binding, it MAY include a public key
associated with the holder, or a reference thereto. 

It is out of the scope of this document to describe how the holder key pair is
established. For example, the holder MAY provide a key pair to the issuer, 
the issuer MAY create the key pair for the holder, or
holder and issuer MAY use pre-established key material.

Note: Examples in this document use `cnf` Claim defined in [@RFC7800] to include raw public key by value in SD-JWT.

## Example 1: SD-JWT

This example and Example 2 in the appendix use the following object as the set
of claims that the Issuer is issuing:

{#example-simple-user_claims}
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

The following non-normative example shows the payload of an SD-JWT. The issuer
is using a flat structure, i.e., all of the claims the `address` claim can only
be disclosed in full.

{#example-simple-sd_jwt_payload}
```json
{
  "iss": "https://example.com/issuer",
  "cnf": {
    "jwk" : {
        "kty": "RSA",
        "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x65659kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjtth8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mTz10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wqf_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSGuxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw",
        "e": "AQAB"
    }
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "sd_hash_alg": "sha-256",
  "sd_digests": {
    "sub": "OMdwkk2HPuiInPypWUWMxot1Y2tStGsLuIcDMjKdXMU",
    "given_name": "AfKKH4a0IZki8MFDythFaFS_Xqzn-wRvAMfiy_VjYpE",
    "family_name": "eUmXmry32JiK_76xMasagkAQQsmSVdW57Ajk18riSF0",
    "email": "-Rcr4fDyjwlM_itcMxoQZCE1QAEwyLJcibEpH114KiE",
    "phone_number": "Jv2nw0C1wP5ASutYNAxrWEnaDRIpiF0eTUAkUOp8F6Y",
    "address": "ZrjKs-RmEAVeAYSzSw6GPFrMpcgctCfaJ6t9qQhbfJ4",
    "birthdate": "qXPRRPdpNaebP8jtbEpO-skF4n7v7ASTh8oLg0mkAdQ"
  }
}
```

The SD-JWT is then signed by the issuer to create a document like the following:

{#example-simple-serialized_sd_jwt}
```
eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZUk
F6VmRsZnhOMjgwTmdIYUEifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1Z
XIiLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInBtNGJPSEJnLW9ZaEF5UFd
6UjU2QVdYM3JVSVhwMTFfSUNEa0dnUzZXM1pXTHRzLWh6d0kzeDY1NjU5a2c0aFZvOWRiR
29DSkUzWkdGX2VhZXRFMzBVaEJVRWdwR3dyRHJRaUo5enFwcm1jRmZyM3F2dmtHanR0aDh
aZ2wxZU0yYkpjT3dFN1BDQkhXVEtXWXMxNTJSN2c2SmcyT1ZwaC1hOHJxLXE3OU1oS0c1U
W9XX21UejEwUVRfNkg0YzdQaldHMWZqaDhocFdObmJQX3B2NmQxelN3WmZjNWZsNnlWUkw
wRFYwVjNsR0hLZTJXcWZfZU5HakJyQkxWa2xEVGs4LXN0WF9NV0xjUi1FR21YQU92MFVCV
2l0U19kWEpLSnUtdlhKeXcxNG5IU0d1eFRJSzJoeDFwdHRNZnQ5Q3N2cWltWEtlRFRVMTR
xUUwxZUU3aWhjdyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiO
iAxNTE2MjQ3MDIyLCAiaGFzaF9hbGciOiAic2hhLTI1NiIsICJzZF9kaWdlc3RzIjogeyJ
zdWIiOiAiT01kd2trMkhQdWlJblB5cFdVV014b3QxWTJ0U3RHc0x1SWNETWpLZFhNVSIsI
CJnaXZlbl9uYW1lIjogIkFmS0tINGEwSVpraThNRkR5dGhGYUZTX1hxem4td1J2QU1maXl
fVmpZcEUiLCAiZmFtaWx5X25hbWUiOiAiZVVtWG1yeTMySmlLXzc2eE1hc2Fna0FRUXNtU
1ZkVzU3QWprMThyaVNGMCIsICJlbWFpbCI6ICItUmNyNGZEeWp3bE1faXRjTXhvUVpDRTF
RQUV3eUxKY2liRXBIMTE0S2lFIiwgInBob25lX251bWJlciI6ICJKdjJudzBDMXdQNUFTd
XRZTkF4cldFbmFEUklwaUYwZVRVQWtVT3A4RjZZIiwgImFkZHJlc3MiOiAiWnJqS3MtUm1
FQVZlQVlTelN3NkdQRnJNcGNnY3RDZmFKNnQ5cVFoYmZKNCIsICJiaXJ0aGRhdGUiOiAic
VhQUlJQZHBOYWViUDhqdGJFcE8tc2tGNG43djdBU1RoOG9MZzBta0FkUSJ9fQ.ET6ScYnZ
dfkTXuBmSK58a760-IlksSi9_Rj4Ju7dPWkg0fvbdCIy5B2fTwkdpqc-zxQ3d-33kbrKHk
gPLnGdTx0bvkQ7ne_PrLSg33l1grXujuznkIfLcnis14py0VvTWaJphdty7FYTm0VhNqQd
tfPFBkGC9NNSGA8A5qM5DmcTUIkOAkfk2cAZ3AZHYE0mmnXHnOwYIwbgB2c3hBtoVPHzse
LTm-rJHXJC7xrvQ3WLI7XVaAXpp0HnV3sGyfS5Z-oKFvmjm-ihH3JcLHeTFZQGOa5D36Or
94C7_kfs7VGjzYWxtpvhn-i7-o7LBLNQLcVWPIJU5y9jm15jMJ6Tnw
```

(Line breaks for presentation only.)


## Format of a SD-JWT Salt/Value Container (SVC)

Besides the SD-JWT itself, the holder needs to learn the raw claim values that
are contained in the SD-JWT, along with the precise input to the hash
calculation, and the salts. There MAY be other information the issuer needs to
communicate to the holder, such as a private key if the issuer selected the
holder key pair.

A SD-JWT Salt/Value Container (SVC) is a JSON object containing at least the
top-level property `sd_release`. Its structure mirrors the one of `sd_digests` in
the SD-JWT, but the values are the inputs to the hash calculations the issuer
used, as strings.

The SVC MAY contain further properties, for example, to transport the holder
private key.

## Example: SVC for the Flat SD-JWT in Example 1

The SVC for Example 1 is as follows:

{#example-simple-svc_payload}
```json
{
  "sd_release": {
    "sub": "{\"s\": \"2GLC42sKQveCfGfryNRN9w\", \"v\": \"6c5c0a49-b589-431d-bae7-219122a9ec2c\"}",
    "given_name": "{\"s\": \"6Ij7tM-a5iVPGboS5tmvVA\", \"v\": \"John\"}",
    "family_name": "{\"s\": \"Qg_O64zqAxe412a108iroA\", \"v\": \"Doe\"}",
    "email": "{\"s\": \"Pc33JM2LchcU_lHggv_ufQ\", \"v\": \"johndoe@example.com\"}",
    "phone_number": "{\"s\": \"lklxF5jMYlGTPUovMNIvCA\", \"v\": \"+1-202-555-0101\"}",
    "address": "{\"s\": \"5bPs1IquZNa0hkaFzzzZNw\", \"v\": {\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}}",
    "birthdate": "{\"s\": \"y1sVU5wdfJahVdgwPgS7RQ\", \"v\": \"1940-01-01\"}"
  }
}
```

Important: As described above, hash digests are calculated over the JSON literal
formed by serializing an object containing the salt, the claim value, and
optionally the claim name. This ensures that issuer and verifier use the same
input to their hash functions and avoids issues with canonicalization of JSON
values that would lead to different hash digests. The SVC therefore maps claim
names to JSON-encoded arrays. 

## Sending SD-JWT and SVC during Issuance

For transporting the SVC together with the SD-JWT from the issuer to the holder,
the SVC is base64url-encoded and appended to the SD-JWT using a period character `.` as the
separator. 

The SVC and SD-JWT are implicitly linked through the hash values of the claims
in the SVC that is included in the SD-JWT. To ensure that the correct SVC and 
SD-JWT pairings are being used, the holder SHOULD verify the binding between
SVC and SD-JWT as defined in the Verification Section of this document.

For Example 1, the combined format looks as follows:

{#example-simple-combined_sd_jwt_svc}
```
eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZUk
F6VmRsZnhOMjgwTmdIYUEifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1Z
XIiLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInBtNGJPSEJnLW9ZaEF5UFd
6UjU2QVdYM3JVSVhwMTFfSUNEa0dnUzZXM1pXTHRzLWh6d0kzeDY1NjU5a2c0aFZvOWRiR
29DSkUzWkdGX2VhZXRFMzBVaEJVRWdwR3dyRHJRaUo5enFwcm1jRmZyM3F2dmtHanR0aDh
aZ2wxZU0yYkpjT3dFN1BDQkhXVEtXWXMxNTJSN2c2SmcyT1ZwaC1hOHJxLXE3OU1oS0c1U
W9XX21UejEwUVRfNkg0YzdQaldHMWZqaDhocFdObmJQX3B2NmQxelN3WmZjNWZsNnlWUkw
wRFYwVjNsR0hLZTJXcWZfZU5HakJyQkxWa2xEVGs4LXN0WF9NV0xjUi1FR21YQU92MFVCV
2l0U19kWEpLSnUtdlhKeXcxNG5IU0d1eFRJSzJoeDFwdHRNZnQ5Q3N2cWltWEtlRFRVMTR
xUUwxZUU3aWhjdyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiO
iAxNTE2MjQ3MDIyLCAiaGFzaF9hbGciOiAic2hhLTI1NiIsICJzZF9kaWdlc3RzIjogeyJ
zdWIiOiAiT01kd2trMkhQdWlJblB5cFdVV014b3QxWTJ0U3RHc0x1SWNETWpLZFhNVSIsI
CJnaXZlbl9uYW1lIjogIkFmS0tINGEwSVpraThNRkR5dGhGYUZTX1hxem4td1J2QU1maXl
fVmpZcEUiLCAiZmFtaWx5X25hbWUiOiAiZVVtWG1yeTMySmlLXzc2eE1hc2Fna0FRUXNtU
1ZkVzU3QWprMThyaVNGMCIsICJlbWFpbCI6ICItUmNyNGZEeWp3bE1faXRjTXhvUVpDRTF
RQUV3eUxKY2liRXBIMTE0S2lFIiwgInBob25lX251bWJlciI6ICJKdjJudzBDMXdQNUFTd
XRZTkF4cldFbmFEUklwaUYwZVRVQWtVT3A4RjZZIiwgImFkZHJlc3MiOiAiWnJqS3MtUm1
FQVZlQVlTelN3NkdQRnJNcGNnY3RDZmFKNnQ5cVFoYmZKNCIsICJiaXJ0aGRhdGUiOiAic
VhQUlJQZHBOYWViUDhqdGJFcE8tc2tGNG43djdBU1RoOG9MZzBta0FkUSJ9fQ.ET6ScYnZ
dfkTXuBmSK58a760-IlksSi9_Rj4Ju7dPWkg0fvbdCIy5B2fTwkdpqc-zxQ3d-33kbrKHk
gPLnGdTx0bvkQ7ne_PrLSg33l1grXujuznkIfLcnis14py0VvTWaJphdty7FYTm0VhNqQd
tfPFBkGC9NNSGA8A5qM5DmcTUIkOAkfk2cAZ3AZHYE0mmnXHnOwYIwbgB2c3hBtoVPHzse
LTm-rJHXJC7xrvQ3WLI7XVaAXpp0HnV3sGyfS5Z-oKFvmjm-ihH3JcLHeTFZQGOa5D36Or
94C7_kfs7VGjzYWxtpvhn-i7-o7LBLNQLcVWPIJU5y9jm15jMJ6Tnw.eyJzZF9yZWxlYXN
lIjogeyJzdWIiOiAie1wic1wiOiBcIjJHTEM0MnNLUXZlQ2ZHZnJ5TlJOOXdcIiwgXCJ2X
CI6IFwiNmM1YzBhNDktYjU4OS00MzFkLWJhZTctMjE5MTIyYTllYzJjXCJ9IiwgImdpdmV
uX25hbWUiOiAie1wic1wiOiBcIjZJajd0TS1hNWlWUEdib1M1dG12VkFcIiwgXCJ2XCI6I
FwiSm9oblwifSIsICJmYW1pbHlfbmFtZSI6ICJ7XCJzXCI6IFwiUWdfTzY0enFBeGU0MTJ
hMTA4aXJvQVwiLCBcInZcIjogXCJEb2VcIn0iLCAiZW1haWwiOiAie1wic1wiOiBcIlBjM
zNKTTJMY2hjVV9sSGdndl91ZlFcIiwgXCJ2XCI6IFwiam9obmRvZUBleGFtcGxlLmNvbVw
ifSIsICJwaG9uZV9udW1iZXIiOiAie1wic1wiOiBcImxrbHhGNWpNWWxHVFBVb3ZNTkl2Q
0FcIiwgXCJ2XCI6IFwiKzEtMjAyLTU1NS0wMTAxXCJ9IiwgImFkZHJlc3MiOiAie1wic1w
iOiBcIjViUHMxSXF1Wk5hMGhrYUZ6enpaTndcIiwgXCJ2XCI6IHtcInN0cmVldF9hZGRyZ
XNzXCI6IFwiMTIzIE1haW4gU3RcIiwgXCJsb2NhbGl0eVwiOiBcIkFueXRvd25cIiwgXCJ
yZWdpb25cIjogXCJBbnlzdGF0ZVwiLCBcImNvdW50cnlcIjogXCJVU1wifX0iLCAiYmlyd
GhkYXRlIjogIntcInNcIjogXCJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRXCIsIFwidlwiOiB
cIjE5NDAtMDEtMDFcIn0ifX0
```

(Line breaks for presentation only.)

## Format of an SD-JWT Release

SD-JWT-R contains claim values and the salts of the claims that the holder 
has consented to release to the Verifier. This enables the Verifier to verify 
the claims received from the holder by computing the hash digests of the claim
values and the salts revealed in the SD-JWT-R using the hashing algorithm 
specified in SD-JWT and comparing them to the hash digests included in SD-JWT.

For each claim, an array of the salt and the claim value is contained in the
`sd_release` object. The structure of `sd_release` object in the SD-JWT-R is the same as in SD-JWT. 

The SD-JWT-R MAY contain further claims, for example, to ensure a binding
to a concrete transaction (in the example the `nonce` and `aud` claims).

When the holder sends the SD-JWT-R to the Verifier, the SD-JWT-R MUST be a JWS 
represented as the JWS Compact Serialization as described in 
Section 7.1 of [@!RFC7515].

If holder binding is desired, the SD-JWT-R is signed by the holder. If no
holder binding is to be used, the `none` algorithm is used, i.e., the document
is not signed. TODO: Change to plain base64 to avoid alg=none issues

## Example: SD-JWT Release for Example 1

The following is a non-normative example of the contents of an SD-JWT-R for Example 1:

{#example-simple-sd_jwt_release_payload}
```json
{
  "nonce": "XZOUco1u_gEPknxS78sWWg",
  "aud": "https://example.com/verifier",
  "sd_release": {
    "given_name": "{\"s\": \"6Ij7tM-a5iVPGboS5tmvVA\", \"v\": \"John\"}",
    "family_name": "{\"s\": \"Qg_O64zqAxe412a108iroA\", \"v\": \"Doe\"}",
    "address": "{\"s\": \"5bPs1IquZNa0hkaFzzzZNw\", \"v\": {\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}}"
  }
}
```

For each claim, a JSON literal that decodes to an object with the and the claim
value (plus optionally the claim name) is contained in the `sd_release` object. 

Again, the SD-JWT-R follows the same structure as the `sd_digests` in the SD-JWT. 

Below is a non-normative example of a representation of the SD-JWT-R JWS Compact
Serialization:

{#example-simple-serialized_sd_jwt_release}
```
eyJhbGciOiAiUlMyNTYiLCAia2lkIjogIkxkeVRYd0F5ZnJpcjRfVjZORzFSYzEwVThKZE
xZVHJFQktKaF9oNWlfclUifQ.eyJub25jZSI6ICJYWk9VY28xdV9nRVBrbnhTNzhzV1dnI
iwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgInNkX3JlbGVhc2U
iOiB7ImdpdmVuX25hbWUiOiAie1wic1wiOiBcIjZJajd0TS1hNWlWUEdib1M1dG12VkFcI
iwgXCJ2XCI6IFwiSm9oblwifSIsICJmYW1pbHlfbmFtZSI6ICJ7XCJzXCI6IFwiUWdfTzY
0enFBeGU0MTJhMTA4aXJvQVwiLCBcInZcIjogXCJEb2VcIn0iLCAiYWRkcmVzcyI6ICJ7X
CJzXCI6IFwiNWJQczFJcXVaTmEwaGthRnp6elpOd1wiLCBcInZcIjoge1wic3RyZWV0X2F
kZHJlc3NcIjogXCIxMjMgTWFpbiBTdFwiLCBcImxvY2FsaXR5XCI6IFwiQW55dG93blwiL
CBcInJlZ2lvblwiOiBcIkFueXN0YXRlXCIsIFwiY291bnRyeVwiOiBcIlVTXCJ9fSJ9fQ.
fw4xRl7m1mDPCZvCTn3GOr2PgBZ--fTKfy7s-GuEifNvzW5KsJaBBFvzdZztm25XGhk29u
w-XwEw00r0hyxXLBvWfA0XbDK3JBmdpOSW1bEyNBdSHPJoeq9Xyts2JN40vJzU2UxNaLKD
aEheWf3F_E52yhHxvMLNdvZJ9FksJdSMK6ZCyGfRJadPN2GhNltqph52sWiFKUyUk_4Rtw
XmT_lF49tWOMZqtG-akN9wrBoMsleM0soA0BXIK10rG5cKZoSNr-u2luzbdZx3CFdAenaq
ScIkluPPcrXBZGYyX2zYUbGQs2RRXnBmox_yl6CvLbb0qTTYhDnDEo_MH-ZtWw
```

(Line breaks for presentation only.)

## Sending SD-JWT and SD-JWT-R during Presentation

The SD-JWT and the SD-JWT-R can be combined into one document using period character `.` as a separator (here for Example 1):

{#example-simple-combined_sd_jwt_sd_jwt_release}
```
eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZUk
F6VmRsZnhOMjgwTmdIYUEifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1Z
XIiLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInBtNGJPSEJnLW9ZaEF5UFd
6UjU2QVdYM3JVSVhwMTFfSUNEa0dnUzZXM1pXTHRzLWh6d0kzeDY1NjU5a2c0aFZvOWRiR
29DSkUzWkdGX2VhZXRFMzBVaEJVRWdwR3dyRHJRaUo5enFwcm1jRmZyM3F2dmtHanR0aDh
aZ2wxZU0yYkpjT3dFN1BDQkhXVEtXWXMxNTJSN2c2SmcyT1ZwaC1hOHJxLXE3OU1oS0c1U
W9XX21UejEwUVRfNkg0YzdQaldHMWZqaDhocFdObmJQX3B2NmQxelN3WmZjNWZsNnlWUkw
wRFYwVjNsR0hLZTJXcWZfZU5HakJyQkxWa2xEVGs4LXN0WF9NV0xjUi1FR21YQU92MFVCV
2l0U19kWEpLSnUtdlhKeXcxNG5IU0d1eFRJSzJoeDFwdHRNZnQ5Q3N2cWltWEtlRFRVMTR
xUUwxZUU3aWhjdyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiO
iAxNTE2MjQ3MDIyLCAiaGFzaF9hbGciOiAic2hhLTI1NiIsICJzZF9kaWdlc3RzIjogeyJ
zdWIiOiAiT01kd2trMkhQdWlJblB5cFdVV014b3QxWTJ0U3RHc0x1SWNETWpLZFhNVSIsI
CJnaXZlbl9uYW1lIjogIkFmS0tINGEwSVpraThNRkR5dGhGYUZTX1hxem4td1J2QU1maXl
fVmpZcEUiLCAiZmFtaWx5X25hbWUiOiAiZVVtWG1yeTMySmlLXzc2eE1hc2Fna0FRUXNtU
1ZkVzU3QWprMThyaVNGMCIsICJlbWFpbCI6ICItUmNyNGZEeWp3bE1faXRjTXhvUVpDRTF
RQUV3eUxKY2liRXBIMTE0S2lFIiwgInBob25lX251bWJlciI6ICJKdjJudzBDMXdQNUFTd
XRZTkF4cldFbmFEUklwaUYwZVRVQWtVT3A4RjZZIiwgImFkZHJlc3MiOiAiWnJqS3MtUm1
FQVZlQVlTelN3NkdQRnJNcGNnY3RDZmFKNnQ5cVFoYmZKNCIsICJiaXJ0aGRhdGUiOiAic
VhQUlJQZHBOYWViUDhqdGJFcE8tc2tGNG43djdBU1RoOG9MZzBta0FkUSJ9fQ.ET6ScYnZ
dfkTXuBmSK58a760-IlksSi9_Rj4Ju7dPWkg0fvbdCIy5B2fTwkdpqc-zxQ3d-33kbrKHk
gPLnGdTx0bvkQ7ne_PrLSg33l1grXujuznkIfLcnis14py0VvTWaJphdty7FYTm0VhNqQd
tfPFBkGC9NNSGA8A5qM5DmcTUIkOAkfk2cAZ3AZHYE0mmnXHnOwYIwbgB2c3hBtoVPHzse
LTm-rJHXJC7xrvQ3WLI7XVaAXpp0HnV3sGyfS5Z-oKFvmjm-ihH3JcLHeTFZQGOa5D36Or
94C7_kfs7VGjzYWxtpvhn-i7-o7LBLNQLcVWPIJU5y9jm15jMJ6Tnw.eyJhbGciOiAiUlM
yNTYiLCAia2lkIjogIkxkeVRYd0F5ZnJpcjRfVjZORzFSYzEwVThKZExZVHJFQktKaF9oN
WlfclUifQ.eyJub25jZSI6ICJYWk9VY28xdV9nRVBrbnhTNzhzV1dnIiwgImF1ZCI6ICJo
dHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgInNkX3JlbGVhc2UiOiB7ImdpdmVuX2
5hbWUiOiAie1wic1wiOiBcIjZJajd0TS1hNWlWUEdib1M1dG12VkFcIiwgXCJ2XCI6IFwi
Sm9oblwifSIsICJmYW1pbHlfbmFtZSI6ICJ7XCJzXCI6IFwiUWdfTzY0enFBeGU0MTJhMT
A4aXJvQVwiLCBcInZcIjogXCJEb2VcIn0iLCAiYWRkcmVzcyI6ICJ7XCJzXCI6IFwiNWJQ
czFJcXVaTmEwaGthRnp6elpOd1wiLCBcInZcIjoge1wic3RyZWV0X2FkZHJlc3NcIjogXC
IxMjMgTWFpbiBTdFwiLCBcImxvY2FsaXR5XCI6IFwiQW55dG93blwiLCBcInJlZ2lvblwi
OiBcIkFueXN0YXRlXCIsIFwiY291bnRyeVwiOiBcIlVTXCJ9fSJ9fQ.fw4xRl7m1mDPCZv
CTn3GOr2PgBZ--fTKfy7s-GuEifNvzW5KsJaBBFvzdZztm25XGhk29uw-XwEw00r0hyxXL
BvWfA0XbDK3JBmdpOSW1bEyNBdSHPJoeq9Xyts2JN40vJzU2UxNaLKDaEheWf3F_E52yhH
xvMLNdvZJ9FksJdSMK6ZCyGfRJadPN2GhNltqph52sWiFKUyUk_4RtwXmT_lF49tWOMZqt
G-akN9wrBoMsleM0soA0BXIK10rG5cKZoSNr-u2luzbdZx3CFdAenaqScIkluPPcrXBZGY
yX2zYUbGQs2RRXnBmox_yl6CvLbb0qTTYhDnDEo_MH-ZtWw
```

(Line breaks for presentation only.)

# Verification

## Verification by the Holder when Receiving SD-JWT and SVC

The holder SHOULD verify the binding between SD-JWT and SVC by performing the following steps:
 1. Check that all the claims in the SVC are present in the SD-JWT and that there are no claims in the SD-JWT that are not in the SVC
 2. Check that the hashes of the claims in the SVC match those in the SD-JWT

## Verification by the Verifier when Receiving SD-JWT and SD-JWT-R

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
    5. Check that the claim `sd_digests` is present in the SD-JWT.
    6. Check that the `sd_hash_alg` claim is present and its value is understand
       and the hash algorithm is deemed secure.
 5. Validate the SD-JWT Release:
    1. If holder binding is required, validate the signature over the SD-JWT using the same steps as for the SD-JWT plus the following steps:
       1. Determine that the public key for the private key that used to sign the SD-JWT-R is bound to the SD-JWT, i.e., the SD-JWT either contains a reference to the public key or contains the public key itself.
       2. Determine that the SD-JWT-R is bound to the current transaction and was created for this verifier (replay protection). This is usually achieved by a `nonce` and `aud` field within the SD-JWT Release.
    2. For each claim in the SD-JWT Release:
       1. Ensure that the claim is present as well in `sd_release` in the SD-JWT.
          If `sd_release` is structured, the claim MUST be present at the same
          place within the structure.
       2. Compute the base64url-encoded hash digest of the JSON literal released
          by the Holder using the `sd_hash_alg` in SD-JWT.
       3. Compare the hash digests computed in the previous step with the one of
          the same claim in the SD-JWT. Accept the claim only when the two hash
          digests match.
       4. Ensure that the claim value in the SD-JWT-R is a JSON-encoded
          object containing at least the keys `s` and `v`, and optionally `n`.
       5. Store the value of the key `v` as the claim value. If `n` is contained
          in the object, use the value of the key `n` as the claim name.
    3. Once all necessary claims have been verified, their values can be
       validated and used according to the requirements of the application. It
       MUST be ensured that all claims required for the application have been
       released.

If any step fails, the input is not valid and processing MUST be aborted.


# Security Considerations {#security_considerations}

## Mandatory hash computation of the revealed claim values by the Verifier

ToDo: add text explaining mechanisms that should be adopted to ensure that 
  verifiers validate the claim values received in SD-JWT-R by calculating the
  hashes of those values and comparing them with the hashes in the SD-JWT: 
  - create a test suite that forces hash computation by the Verifiers, 
    and includes negative test cases in test vectors
  - use only implementations/libraries that are compliant to the test suite 
  - etc.

## Mandatory signing of the SD-JWT

The SD-JWT MUST be signed by the issuer to protect integrity of the issued
claims. An attacker can modify or add claims if an SD-JWT is not signed (e.g.,
change the "email" attribute to take over the victim's account or add an
attribute indicating a fake academic qualification).

The verifier MUST always check the SD-JWT signature to ensure that the SD-JWT
has not been tampered with since its issuance. If the signature on the SD-JWT
cannot be verified, the SD-JWT MUST be rejected. 

## Entropy and Uniqueness of the salt

The security model relies on the fact that the salt is not learned or guessed by
the attacker. It is vitally important to adhere to this principle. As such, the
salt MUST be created in such a manner that it is cryptographically random,
long enough and has high entropy that it is not practical for the attacker to
guess. Each salt value MUST be unique.

## Minimum length of the salt

The length of the randomly-generated portion of the salt MUST be at least 128 bits.

## Choice of a hash function

For the security of this scheme, the hash function is required to be preimage and collision
resistant, i.e., it is infeasible to calculate the salt and claim value that result in
a particular digest, and it is infeasible to find a different salt and claim value pair that
result in a matching digest, respectively.

Furthermore the hash algorithms MD2, MD4, MD5, RIPEMD-160, and SHA-1 
revealed fundamental weaknesses and they MUST NOT be used.

## Holder Binding {#holder_binding_security}
TBD

## Blinding Claim Names

Issuers that chose to blind claim names MUST ensure not to inadvertently leak
information about the blinded claim names to verifiers. In particular, issuers
MUST choose placeholder claim names accordingly. It is RECOMMENDED to use
cryptographically random values with at least 128 bits of entropy as placeholder
claim names.

The order of elements in JSON-encoded objects is not relevant to applications,
but the order may reveal information about the blinded claim name to the
verifier. It is therefore RECOMMENDED to ensure that the order is shuffled or
otherwise hidden (e.g., alphabetically ordered using the blinded claim names).

# Privacy Considerations {#privacy_considerations}

## Claim Names

By default, claim names are not blinded in an SD-JWT. In this case, even when
the claim's value is not known to a verifier, the claim name can disclose some
information to the verifier. For example, if the SD-JWT contains a claim named
`super_secret_club_membership_no`, the verifier might assume that the end-user
is a member of the Super Secret Club. 

Blinding claim names can help to avoid this potential privacy issue. In many
cases, however, verifiers can already deduce this or similar information just
from the identification of the issuer and the schema used for the SD-JWT.
Blinding claim names might not provide additional privacy if this is the case.

## Unlinkability 

Colluding issuer/verifier or verifier/verifier pairs could link issuance/presentation or two presentation sessions
to the same user on the basis of unique values encoded in the SD-JWT
(issuer signature, salts, digests, etc.). More advanced cryptographic schemes, outside the scope of
this specification, can be used to prevent this type of linkability.

# Acknowledgements {#Acknowledgements}
      
We would like to thank 
Alen Horvat, 
Brian Campbell, 
Christian Paquin, 
Fabian Hauck,
Giuseppe De Marco, 
Kushal Das, 
Mike Jones, 
Nat Sakimura,
Pieter Kasselman, and
Torsten Lodderstedt
for their contributions (some of which substantial) to this draft and to the initial set of implementations.

The work on this draft was started at OAuth Security Workshop 2022 in Trondheim, Norway.


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

<reference anchor="VC_DATA" target="https://www.w3.org/TR/vc_data">
  <front>
    <title>Verifiable Credentials Data Model 1.0</title>
    <author fullname="Manu Sporny">
      <organization>Digital Bazaar</organization>
    </author>
    <author fullname="Grant Noble">
      <organization>ConsenSys</organization>
    </author>
    <author fullname="Dave Longley">
      <organization>Digital Bazaar</organization>
    </author>
    <author fullname="Daniel C. Burnett">
      <organization>ConsenSys</organization>
    </author>
    <author fullname="Brent Zundel">
      <organization>Evernym</organization>
    </author>
    <author fullname="David Chadwick">
      <organization>University of Kent</organization>
    </author>
    <date day="19" month="Nov" year="2019" />
  </front>
</reference>

{backmatter}

# Additional Examples

## Example 2 - Structured SD-JWT
This non-normative example is based on the same claim values as Example 1, but
this time the issuer decided to create a structured object for the hashes. This
allows for the release of individual members of the address claim separately.

{#example-simple_structured-sd_jwt_payload}
```json
{
  "iss": "https://example.com/issuer",
  "cnf": {
    "jwk" : {
        "kty": "RSA",
        "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x65659kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjtth8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mTz10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wqf_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSGuxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw",
        "e": "AQAB"
    }
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "sd_hash_alg": "sha-256",
  "sd_digests": {
    "sub": "OMdwkk2HPuiInPypWUWMxot1Y2tStGsLuIcDMjKdXMU",
    "given_name": "AfKKH4a0IZki8MFDythFaFS_Xqzn-wRvAMfiy_VjYpE",
    "family_name": "eUmXmry32JiK_76xMasagkAQQsmSVdW57Ajk18riSF0",
    "email": "-Rcr4fDyjwlM_itcMxoQZCE1QAEwyLJcibEpH114KiE",
    "phone_number": "Jv2nw0C1wP5ASutYNAxrWEnaDRIpiF0eTUAkUOp8F6Y",
    "address": {
      "street_address": "n25N6kth9N0CwjZXHeth1gfovg8_I8fGyzeY0qeLp0k",
      "locality": "gJVL_TKoT_SbA4_sv0klLTkg-YEGzVUkC-6egxegsz0",
      "region": "zXbstGPuPq2cPJfyD_-HlmqVyFMf03xH-FbeotXxdbo",
      "country": "pN-5CZ5hbumsPvLKUADm4Ott6gu0E4xj09s4Z51yb8U"
    },
    "birthdate": "UxsvgkUgPnawP6wY4hmxJ_jqiNNKni62zrX7hQOUsys"
  }
}
```

The SVC for this SD-JWT is as follows:

{#example-simple_structured-svc_payload}
```json
{
  "sd_release": {
    "sub": "{\"s\": \"2GLC42sKQveCfGfryNRN9w\", \"v\": \"6c5c0a49-b589-431d-bae7-219122a9ec2c\"}",
    "given_name": "{\"s\": \"6Ij7tM-a5iVPGboS5tmvVA\", \"v\": \"John\"}",
    "family_name": "{\"s\": \"Qg_O64zqAxe412a108iroA\", \"v\": \"Doe\"}",
    "email": "{\"s\": \"Pc33JM2LchcU_lHggv_ufQ\", \"v\": \"johndoe@example.com\"}",
    "phone_number": "{\"s\": \"lklxF5jMYlGTPUovMNIvCA\", \"v\": \"+1-202-555-0101\"}",
    "address": {
      "street_address": "{\"s\": \"5bPs1IquZNa0hkaFzzzZNw\", \"v\": \"123 Main St\"}",
      "locality": "{\"s\": \"y1sVU5wdfJahVdgwPgS7RQ\", \"v\": \"Anytown\"}",
      "region": "{\"s\": \"C9GSoujviJquEgYfojCb1A\", \"v\": \"Anystate\"}",
      "country": "{\"s\": \"H3o1uswP760Fi2yeGdVCEQ\", \"v\": \"US\"}"
    },
    "birthdate": "{\"s\": \"M0Jb57t41ubrkSuyrDT3xA\", \"v\": \"1940-01-01\"}"
  }
}
```

An SD-JWT-R for the SD-JWT above that discloses only `region` and `country` of
the `address` property:

{#example-simple_structured-sd_jwt_release_payload}
```json
{
  "nonce": "XZOUco1u_gEPknxS78sWWg",
  "aud": "https://example.com/verifier",
  "sd_release": {
    "given_name": "{\"s\": \"6Ij7tM-a5iVPGboS5tmvVA\", \"v\": \"John\"}",
    "family_name": "{\"s\": \"Qg_O64zqAxe412a108iroA\", \"v\": \"Doe\"}",
    "birthdate": "{\"s\": \"M0Jb57t41ubrkSuyrDT3xA\", \"v\": \"1940-01-01\"}",
    "address": {
      "region": "{\"s\": \"C9GSoujviJquEgYfojCb1A\", \"v\": \"Anystate\"}",
      "country": "{\"s\": \"H3o1uswP760Fi2yeGdVCEQ\", \"v\": \"US\"}"
    }
  }
}
```

## Example 3 - Complex Structured SD-JWT

In this example, a complex object such as those used for OIDC4IDA (todo reference) is used.

In this example, the Issuer is using a following object as a set of claims to issue to the Holder:

{#example-complex-user_claims}
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

{#example-complex-sd_jwt_payload}
```json
{
  "iss": "https://example.com/issuer",
  "cnf": {
    "jwk" : {
        "kty": "RSA",
        "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x65659kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjtth8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mTz10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wqf_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSGuxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw",
        "e": "AQAB"
    }
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "sd_hash_alg": "sha-256",
  "sd_digests": {
    "verified_claims": {
      "verification": {
        "trust_framework": "T7ivxsfuy-nAuECeh0utPEX8cSlc7QflJDE0RqtWDMU",
        "time": "_ecCQoXSR8t9esur66ZwWwC6u4xLuVELjmwFgpRZqcQ",
        "verification_process": "BolwKKvU8N7uUhjN2aGH2T54wjXpkcOz5sC9PkIP4s4",
        "evidence": [
          {
            "type": "7jBlUZkZn1Gfj9mybqlJGzTb2z8KcNNHU0IV4B8MxOM",
            "method": "BRQgcT09gdBqO-MLTka8d6dlCshZCUNpFgsZoet5I-o",
            "time": "-PVLNSmbkCHLp8S7i077YnHZV0yE8gyKWLpWV2o8FJE",
            "document": {
              "type": "vzDHD-6hQqZ5lSw_7acK1lErxSh3E6dO0zlUYM2hDvw",
              "issuer": {
                "name": "us9T9ufVdSmytSmjrtdN_TUI0ai3_JNM3q-0qx0CXk4",
                "country": "uItKtPRZQBB9v5THHOdi02ALjD0MH0U6jjHDLe91NnY"
              },
              "number": "QNNXwo3siOWdqNivKBnFsD4X8gZxVIgu3tv6dfpZhUc",
              "date_of_issuance": "AYWQphnOlFFN9oSVvtBr_iYCKYlucTi3lsMrXebebgc",
              "date_of_expiry": "JIk-APYHW3qy60rvGyFswDCTMfAbBXZyyrZEn8NsBhU"
            }
          }
        ]
      },
      "claims": {
        "given_name": "hZtT6FZBzxAeByDUkFJTeqTCpTd2cQKx6MDPkGvVCRE",
        "family_name": "5yLYGVxPSfXynhcopbIcrFe0_sMGxv_-6THZAu4eWnU",
        "birthdate": "aB3eabkYkRF2DJiFyYtkcC12VECREaqR8UofmXyHhcU",
        "place_of_birth": {
          "country": "m7zAMJASE0TJkMRHhCfC8QEXAZhS_8DGdLqOsm8Zp7k",
          "locality": "iLkBIeq-3PD7pxeMz99Of12IIH7WqXFrgHxvdCJz5Sk"
        },
        "nationalities": "lQjcMf0lXA-IPW5aQHEX2Ln-Xz5ZE8oG3RY7ZVM4sTw",
        "address": "1H0qniEo7vEP_SLiVOEx5F5oiPS-IEoCW_L9wj1IYWA"
      }
    },
    "birth_middle_name": "KpRjGCm3uykvCGFIDrVJ7iTMQhWakBmCItHbAa6vnZE",
    "salutation": "IoY5e03e65CUrnaMcRDmPCm0RWPEFE4mVkoCsK86agA",
    "msisdn": "XupJick4P8bxaz20kx_VOwbGU1cgslhAUG6IE-tDjms"
  }
}
```

The SD-JWT is then signed by the issuer to create a document like the following:

{#example-complex-serialized_sd_jwt}
```
eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZUk
F6VmRsZnhOMjgwTmdIYUEifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1Z
XIiLCAic3ViX2p3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInBtNGJPSEJnLW9ZaEF5UFd
6UjU2QVdYM3JVSVhwMTFfSUNEa0dnUzZXM1pXTHRzLWh6d0kzeDY1NjU5a2c0aFZvOWRiR
29DSkUzWkdGX2VhZXRFMzBVaEJVRWdwR3dyRHJRaUo5enFwcm1jRmZyM3F2dmtHanR0aDh
aZ2wxZU0yYkpjT3dFN1BDQkhXVEtXWXMxNTJSN2c2SmcyT1ZwaC1hOHJxLXE3OU1oS0c1U
W9XX21UejEwUVRfNkg0YzdQaldHMWZqaDhocFdObmJQX3B2NmQxelN3WmZjNWZsNnlWUkw
wRFYwVjNsR0hLZTJXcWZfZU5HakJyQkxWa2xEVGs4LXN0WF9NV0xjUi1FR21YQU92MFVCV
2l0U19kWEpLSnUtdlhKeXcxNG5IU0d1eFRJSzJoeDFwdHRNZnQ5Q3N2cWltWEtlRFRVMTR
xUUwxZUU3aWhjdyIsICJlIjogIkFRQUIifSwgImlhdCI6IDE1MTYyMzkwMjIsICJleHAiO
iAxNTE2MjQ3MDIyLCAiaGFzaF9hbGciOiAic2hhLTI1NiIsICJzZF9kaWdlc3RzIjogeyJ
2ZXJpZmllZF9jbGFpbXMiOiB7InZlcmlmaWNhdGlvbiI6IHsidHJ1c3RfZnJhbWV3b3JrI
jogIlQ3aXZ4c2Z1eS1uQXVFQ2VoMHV0UEVYOGNTbGM3UWZsSkRFMFJxdFdETVUiLCAidGl
tZSI6ICJfZWNDUW9YU1I4dDllc3VyNjZad1d3QzZ1NHhMdVZFTGptd0ZncFJacWNRIiwgI
nZlcmlmaWNhdGlvbl9wcm9jZXNzIjogIkJvbHdLS3ZVOE43dVVoak4yYUdIMlQ1NHdqWHB
rY096NXNDOVBrSVA0czQiLCAiZXZpZGVuY2UiOiBbeyJ0eXBlIjogIjdqQmxVWmtabjFHZ
mo5bXlicWxKR3pUYjJ6OEtjTk5IVTBJVjRCOE14T00iLCAibWV0aG9kIjogIkJSUWdjVDA
5Z2RCcU8tTUxUa2E4ZDZkbENzaFpDVU5wRmdzWm9ldDVJLW8iLCAidGltZSI6ICItUFZMT
lNtYmtDSExwOFM3aTA3N1luSFpWMHlFOGd5S1dMcFdWMm84RkpFIiwgImRvY3VtZW50Ijo
geyJ0eXBlIjogInZ6REhELTZoUXFaNWxTd183YWNLMWxFcnhTaDNFNmRPMHpsVVlNMmhEd
nciLCAiaXNzdWVyIjogeyJuYW1lIjogInVzOVQ5dWZWZFNteXRTbWpydGROX1RVSTBhaTN
fSk5NM3EtMHF4MENYazQiLCAiY291bnRyeSI6ICJ1SXRLdFBSWlFCQjl2NVRISE9kaTAyQ
UxqRDBNSDBVNmpqSERMZTkxTm5ZIn0sICJudW1iZXIiOiAiUU5OWHdvM3NpT1dkcU5pdkt
CbkZzRDRYOGdaeFZJZ3UzdHY2ZGZwWmhVYyIsICJkYXRlX29mX2lzc3VhbmNlIjogIkFZV
1FwaG5PbEZGTjlvU1Z2dEJyX2lZQ0tZbHVjVGkzbHNNclhlYmViZ2MiLCAiZGF0ZV9vZl9
leHBpcnkiOiAiSklrLUFQWUhXM3F5NjBydkd5RnN3RENUTWZBYkJYWnl5clpFbjhOc0JoV
SJ9fV19LCAiY2xhaW1zIjogeyJnaXZlbl9uYW1lIjogImhadFQ2RlpCenhBZUJ5RFVrRkp
UZXFUQ3BUZDJjUUt4Nk1EUGtHdlZDUkUiLCAiZmFtaWx5X25hbWUiOiAiNXlMWUdWeFBTZ
lh5bmhjb3BiSWNyRmUwX3NNR3h2Xy02VEhaQXU0ZVduVSIsICJiaXJ0aGRhdGUiOiAiYUI
zZWFia1lrUkYyREppRnlZdGtjQzEyVkVDUkVhcVI4VW9mbVh5SGhjVSIsICJwbGFjZV9vZ
l9iaXJ0aCI6IHsiY291bnRyeSI6ICJtN3pBTUpBU0UwVEprTVJIaENmQzhRRVhBWmhTXzh
ER2RMcU9zbThacDdrIiwgImxvY2FsaXR5IjogImlMa0JJZXEtM1BEN3B4ZU16OTlPZjEyS
UlIN1dxWEZyZ0h4dmRDSno1U2sifSwgIm5hdGlvbmFsaXRpZXMiOiAibFFqY01mMGxYQS1
JUFc1YVFIRVgyTG4tWHo1WkU4b0czUlk3WlZNNHNUdyIsICJhZGRyZXNzIjogIjFIMHFua
UVvN3ZFUF9TTGlWT0V4NUY1b2lQUy1JRW9DV19MOXdqMUlZV0EifX0sICJiaXJ0aF9taWR
kbGVfbmFtZSI6ICJLcFJqR0NtM3V5a3ZDR0ZJRHJWSjdpVE1RaFdha0JtQ0l0SGJBYTZ2b
lpFIiwgInNhbHV0YXRpb24iOiAiSW9ZNWUwM2U2NUNVcm5hTWNSRG1QQ20wUldQRUZFNG1
Wa29Dc0s4NmFnQSIsICJtc2lzZG4iOiAiWHVwSmljazRQOGJ4YXoyMGt4X1ZPd2JHVTFjZ
3NsaEFVRzZJRS10RGptcyJ9fQ.NqoON2sW8WuTtwBfaTCKQ8_axpGR2FRBuEZ7IPpIrABB
Ly-QZCXBYUpEHJf5DioyAk7KEQH50DBszjXwZe3HQqzabv2gby2Y0Bq0I-fRBk2XNwPiFQ
rfIB7bGRZUSHLXYgNXyq1mU0cfAxzWssskWjQbhWHeCODB38x90UR4zl5oh6nstLPNUwEf
VnZk2O26EwvRN7nP7bXX7ia2UM1xqtu9tgnUFR1j1iFtLSjwDOVezFnJNQFdGuyLdIUcx7
O1lhNwak4GSiZSDV6I7n9i8BeYtptewVhCAg1VIp-A1nHnFRdZReO5jdV8r1I7R6eVQIb4
fdFwdbtAtMLRVI3xcQ
```

(Line breaks for presentation only.)

A SD-JWT-R for some of the claims:

{#example-complex-sd_jwt_release_payload}
```json
{
  "nonce": "XZOUco1u_gEPknxS78sWWg",
  "aud": "https://example.com/verifier",
  "sd_release": {
    "verified_claims": {
      "verification": {
        "trust_framework": "{\"s\": \"2GLC42sKQveCfGfryNRN9w\", \"v\": \"de_aml\"}",
        "time": "{\"s\": \"6Ij7tM-a5iVPGboS5tmvVA\", \"v\": \"2012-04-23T18:25Z\"}",
        "evidence": [
          {
            "type": "{\"s\": \"Pc33JM2LchcU_lHggv_ufQ\", \"v\": \"document\"}"
          }
        ]
      },
      "claims": {
        "given_name": "{\"s\": \"4KyR32oIZt-zkWvFqbULKg\", \"v\": \"Max\"}",
        "family_name": "{\"s\": \"flNP1ncMz9Lg-c9qMIz_9g\", \"v\": \"Meier\"}",
        "birthdate": "{\"s\": \"t8EA-tKsh5wZMB6bpjLfTQ\", \"v\": \"1956-01-28\"}",
        "place_of_birth": {
          "country": "{\"s\": \"yh3cQSKnhdGmpVgd3ydH2Q\", \"v\": \"DE\"}"
        }
      }
    }
  }
}
```

## Example 4 - W3C Verifiable Credentials Data Model

This example illustrates how the artifacts defined in this specification can be
represented using W3C Verifiable Credentials Data Model as defined in
[@VC_DATA].

Below is a non-normative example of an SD-JWT represented as a verifiable credential 
encoded as JSON and signed as JWS compliant to [@VC_DATA].

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
  "sd_digests": {
    "given_name": "fUMdn88aaoyKTHrvZd6AuLmPraGhPJ0zF5r_JhxCVZs",
    "family_name": "9h5vgv6TpFV6GmnPtugiMLl5tHetHeb5X_2cKHjN7cw",
    "birthdate": "fvLCnDm3r4VSYcBF3pIlXP4ulEoHuHOfG_YmFZEuxpQ"
  }
}
```

Below is a non-normative example of an SD-JWT-R represented as a verifiable presentation
encoded as JSON and signed as a JWS compliant to [@VC_DATA].

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
  "sd_release": {
    "given_name": "[\"6Ij7tM-a5iVPGboS5tmvVA\", \"John\"]",
    "family_name": "[\"eI8ZWm9QnKPpNPeNenHdhQ\", \"Doe\"]",
    "birthdate": "[\"5bPs1IquZNa0hkaFzzzZNw\", \"1940-01-01\"]"
  }
}
```

# Blinding Claim Names

## Example 5: Some Blinded Claims

The following shows the user information used in this example, included a claim named `secret_club_membership_no`:

{#example-simple_structured_some_blinded-user_claims}
```json
{
  "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
  "given_name": "John",
  "family_name": "Doe",
  "email": "johndoe@example.com",
  "phone_number": "+1-202-555-0101",
  "secret_club_membership_no": "23",
  "other_secret_club_membership_no": "42",
  "address": {
    "street_address": "123 Main St",
    "locality": "Anytown",
    "region": "Anystate",
    "country": "US"
  },
  "birthdate": "1940-01-01"
}
```

Hiding just this claim, the following SD-JWT payload would result:

{#example-simple_structured_some_blinded-sd_jwt_payload}
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
  "hash_alg": "sha-256",
  "sd_digests": {
    "sub": "OMdwkk2HPuiInPypWUWMxot1Y2tStGsLuIcDMjKdXMU",
    "given_name": "AfKKH4a0IZki8MFDythFaFS_Xqzn-wRvAMfiy_VjYpE",
    "family_name": "eUmXmry32JiK_76xMasagkAQQsmSVdW57Ajk18riSF0",
    "email": "-Rcr4fDyjwlM_itcMxoQZCE1QAEwyLJcibEpH114KiE",
    "phone_number": "Jv2nw0C1wP5ASutYNAxrWEnaDRIpiF0eTUAkUOp8F6Y",
    "5a2W0_NrlEZzfqmk_7Pq-w": "gc8VzGTImYRXzP6j7q5RomXt2C_wtsOJ3hAHJdTuEIY",
    "other_secret_club_membership_no": "IirAwgN-MubteYvJ4fmq04p9PnpRTf7hqg0dzSWRboA",
    "address": {
      "street_address": "o_yJIdfhKuKVzOF7i1EuakzC5ghd99CX8_nitm-DsRM",
      "locality": "ogNqsvRqK0-ZPZc9C3Z4_6APvywm-lrm0oF2gcVtl_4",
      "region": "8kFihRLSkEheK0zbEsQ3zKXt8csE6OXJE_jv3032BbU",
      "country": "11IMcoA18LrFSpbysx-uqe7N3I3-QZKwCJqYeQuOUY4"
    },
    "birthdate": "PNtcyxm0Q5PyiBuG4f6eAbK6h4tF2FffwG3xqknZ_5A"
  }
}
```

In the SVC it can be seen that the blinded claim's original name is `secret_club_membership_no`:


{#example-simple_structured_some_blinded-svc_payload}
```json
{
  "sd_release": {
    "sub": "{\"s\": \"2GLC42sKQveCfGfryNRN9w\", \"v\": \"6c5c0a49-b589-431d-bae7-219122a9ec2c\"}",
    "given_name": "{\"s\": \"6Ij7tM-a5iVPGboS5tmvVA\", \"v\": \"John\"}",
    "family_name": "{\"s\": \"Qg_O64zqAxe412a108iroA\", \"v\": \"Doe\"}",
    "email": "{\"s\": \"Pc33JM2LchcU_lHggv_ufQ\", \"v\": \"johndoe@example.com\"}",
    "phone_number": "{\"s\": \"lklxF5jMYlGTPUovMNIvCA\", \"v\": \"+1-202-555-0101\"}",
    "5a2W0_NrlEZzfqmk_7Pq-w": "{\"s\": \"5bPs1IquZNa0hkaFzzzZNw\", \"v\": \"23\", \"n\": \"secret_club_membership_no\"}",
    "other_secret_club_membership_no": "{\"s\": \"y1sVU5wdfJahVdgwPgS7RQ\", \"v\": \"42\"}",
    "address": {
      "street_address": "{\"s\": \"C9GSoujviJquEgYfojCb1A\", \"v\": \"123 Main St\"}",
      "locality": "{\"s\": \"H3o1uswP760Fi2yeGdVCEQ\", \"v\": \"Anytown\"}",
      "region": "{\"s\": \"M0Jb57t41ubrkSuyrDT3xA\", \"v\": \"Anystate\"}",
      "country": "{\"s\": \"eK5o5pHfgupPpltj1qhAJw\", \"v\": \"US\"}"
    },
    "birthdate": "{\"s\": \"WpxJrFuX8uSi2p4ht09jvw\", \"v\": \"1940-01-01\"}"
  }
}
```

The verifier would learn this information via the SD-JWT-R:

{#example-simple_structured_some_blinded-sd_jwt_release_payload}
```json
{
  "nonce": "XZOUco1u_gEPknxS78sWWg",
  "aud": "https://example.com/verifier",
  "sd_release": {
    "given_name": "{\"s\": \"6Ij7tM-a5iVPGboS5tmvVA\", \"v\": \"John\"}",
    "family_name": "{\"s\": \"Qg_O64zqAxe412a108iroA\", \"v\": \"Doe\"}",
    "birthdate": "{\"s\": \"WpxJrFuX8uSi2p4ht09jvw\", \"v\": \"1940-01-01\"}",
    "address": {
      "region": "{\"s\": \"M0Jb57t41ubrkSuyrDT3xA\", \"v\": \"Anystate\"}",
      "country": "{\"s\": \"eK5o5pHfgupPpltj1qhAJw\", \"v\": \"US\"}"
    },
    "5a2W0_NrlEZzfqmk_7Pq-w": "{\"s\": \"5bPs1IquZNa0hkaFzzzZNw\", \"v\": \"23\", \"n\": \"secret_club_membership_no\"}"
  }
}
```

The verifier would decode the data as follows:


{#example-simple_structured_some_blinded-verified_contents}
```json
{
  "given_name": "John",
  "family_name": "Doe",
  "birthdate": "1940-01-01",
  "address": {
    "region": "Anystate",
    "country": "US"
  },
  "secret_club_membership_no": "23"
}
```
## Example 6: All Claim Names Blinded

In this example, all claim names are blinded. The following user data is used:

{#example-simple_structured_all_blinded-user_claims}
```json
{
  "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
  "given_name": "John",
  "family_name": "Doe",
  "email": "johndoe@example.com",
  "phone_number": "+1-202-555-0101",
  "secret_club_membership_no": "23",
  "address": {
    "street_address": "123 Main St",
    "locality": "Anytown",
    "region": "Anystate",
    "country": "US"
  },
  "birthdate": "1940-01-01"
}
```


The resulting SD-JWT payload:

{#example-simple_structured_all_blinded-sd_jwt_payload}
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
  "hash_alg": "sha-256",
  "sd_digests": {
    "eluV5Og3gSNII8EYnsxA_A": "bvPLqohL5ROmk2UsuNffH8C1wx9o-ipm-G4SkUwrpAE",
    "eI8ZWm9QnKPpNPeNenHdhQ": "pCtjs0hC2Klhsnpe7BIqnGAsXlyXXC-lAEgX6isoYVM",
    "AJx-095VPrpTtN4QMOqROA": "HS1Ht-bTrXsSTw9JdcHIbTFDkEI_IY52_cmzUgxWZ0k",
    "G02NSrQfjFXQ7Io09syajA": "M2YQ_j8OPPBK3ZLhPPP6_AdSa2-rug2urYjgk_ML_QM",
    "nPuoQnkRFq3BIeAm7AnXFA": "-Brzrp2cs-8nLs7rQI89YJ76s3PrbVe3n_5hlYCy1cE",
    "5a2W0_NrlEZzfqmk_7Pq-w": "gc8VzGTImYRXzP6j7q5RomXt2C_wtsOJ3hAHJdTuEIY",
    "address": {
      "HbQ4X8srVW3QDxnIJdqyOA": "39o5dKobVi8c0dLpg4sjd7zW18UONRra0ht9mgu4hec",
      "kx5kF17V-x0JmwUx9vgvtw": "wqueD5ABJ3bTyGSckOMpzI7YUvcCO2l-40vi6JMYsYY",
      "OBKlTVlvLg-AdwqYGbP8ZA": "S11dsdFN97YtrA2o3yZ0eBbf1zn-izejORU-fyMtynI",
      "DsmtKNgpV4dAHpjrcaosAw": "-0XEQHSNzMu244QaOpLmPD3JkdZN8SrqbEQ4VDufu9A"
    },
    "j7ADdb0UVb0Li0ciPcP0ew": "X_v1hrkQIH_0LBM8TncMMTBzYN9UJc8FmJRda7yfY8g"
  }
}
```

The SVC:


{#example-simple_structured_all_blinded-svc_payload}
```json
{
  "sd_release": {
    "eluV5Og3gSNII8EYnsxA_A": "{\"s\": \"2GLC42sKQveCfGfryNRN9w\", \"v\": \"6c5c0a49-b589-431d-bae7-219122a9ec2c\", \"n\": \"sub\"}",
    "eI8ZWm9QnKPpNPeNenHdhQ": "{\"s\": \"6Ij7tM-a5iVPGboS5tmvVA\", \"v\": \"John\", \"n\": \"given_name\"}",
    "AJx-095VPrpTtN4QMOqROA": "{\"s\": \"Qg_O64zqAxe412a108iroA\", \"v\": \"Doe\", \"n\": \"family_name\"}",
    "G02NSrQfjFXQ7Io09syajA": "{\"s\": \"Pc33JM2LchcU_lHggv_ufQ\", \"v\": \"johndoe@example.com\", \"n\": \"email\"}",
    "nPuoQnkRFq3BIeAm7AnXFA": "{\"s\": \"lklxF5jMYlGTPUovMNIvCA\", \"v\": \"+1-202-555-0101\", \"n\": \"phone_number\"}",
    "5a2W0_NrlEZzfqmk_7Pq-w": "{\"s\": \"5bPs1IquZNa0hkaFzzzZNw\", \"v\": \"23\", \"n\": \"secret_club_membership_no\"}",
    "address": {
      "HbQ4X8srVW3QDxnIJdqyOA": "{\"s\": \"y1sVU5wdfJahVdgwPgS7RQ\", \"v\": \"123 Main St\", \"n\": \"street_address\"}",
      "kx5kF17V-x0JmwUx9vgvtw": "{\"s\": \"C9GSoujviJquEgYfojCb1A\", \"v\": \"Anytown\", \"n\": \"locality\"}",
      "OBKlTVlvLg-AdwqYGbP8ZA": "{\"s\": \"H3o1uswP760Fi2yeGdVCEQ\", \"v\": \"Anystate\", \"n\": \"region\"}",
      "DsmtKNgpV4dAHpjrcaosAw": "{\"s\": \"M0Jb57t41ubrkSuyrDT3xA\", \"v\": \"US\", \"n\": \"country\"}"
    },
    "j7ADdb0UVb0Li0ciPcP0ew": "{\"s\": \"eK5o5pHfgupPpltj1qhAJw\", \"v\": \"1940-01-01\", \"n\": \"birthdate\"}"
  }
}
```

Here, the holder decided only to release a subset of the claims to the verifier:

{#example-simple_structured_all_blinded-sd_jwt_release_payload}
```json
{
  "nonce": "XZOUco1u_gEPknxS78sWWg",
  "aud": "https://example.com/verifier",
  "sd_release": {
    "eI8ZWm9QnKPpNPeNenHdhQ": "{\"s\": \"6Ij7tM-a5iVPGboS5tmvVA\", \"v\": \"John\", \"n\": \"given_name\"}",
    "AJx-095VPrpTtN4QMOqROA": "{\"s\": \"Qg_O64zqAxe412a108iroA\", \"v\": \"Doe\", \"n\": \"family_name\"}",
    "j7ADdb0UVb0Li0ciPcP0ew": "{\"s\": \"eK5o5pHfgupPpltj1qhAJw\", \"v\": \"1940-01-01\", \"n\": \"birthdate\"}",
    "address": {
      "OBKlTVlvLg-AdwqYGbP8ZA": "{\"s\": \"H3o1uswP760Fi2yeGdVCEQ\", \"v\": \"Anystate\", \"n\": \"region\"}",
      "DsmtKNgpV4dAHpjrcaosAw": "{\"s\": \"M0Jb57t41ubrkSuyrDT3xA\", \"v\": \"US\", \"n\": \"country\"}"
    }
  }
}
```

The verifier would decode the SD-JWT-R and SD-JWT as follows:


{#example-simple_structured_all_blinded-verified_contents}
```json
{
  "given_name": "John",
  "family_name": "Doe",
  "birthdate": "1940-01-01",
  "address": {
    "region": "Anystate",
    "country": "US"
  }
}
```




# Document History

   [[ To be removed from the final specification ]]

   -02

   *  Added acknowledgements
   *  Improved Security Considerations
   *  Stressed uniqueness requirements for salts
   *  Python reference implementation clean-up and refactoring
   *  hash_alg renamed to sd_hash_alg

   -01
   
   *  Editorial fixes
   *  Added `hash_alg` claim
   *  Renamed `_sd` to `sd_digests` and `sd_release`
   *  Added descriptions on holder binding - more work to do
   *  Clarify that signing the SD-JWT is mandatory

   -00

   *  Renamed to SD-JWT (focus on JWT instead of JWS since signature is optional)
   *  Make holder binding optional
   *  Rename proof to release, since when there is no signature, the term "proof" can be misleading
   *  Improved the structure of the description
   *  Described verification steps
   *  All examples generated from python demo implementation
   *  Examples for structured objects


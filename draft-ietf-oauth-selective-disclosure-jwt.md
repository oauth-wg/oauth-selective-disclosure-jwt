%%%
title = "Selective Disclosure for JWTs (SD-JWT)"
abbrev = "SD-JWT"
ipr = "trust200902"
area = "Security"
workgroup = "Web Authorization Protocol"
keyword = ["security", "oauth2"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-ietf-oauth-selective-disclosure-jwt-latest"
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

The JSON-based representation of claims in a signed JSON Web Token (JWT) [@!RFC7519] is
secured against modification using JSON Web Signature (JWS) [@!RFC7515] digital
signatures. A consumer of a signed JWT that has checked the
signature can safely assume that the contents of the token have not been
modified.  However, anyone receiving an unencrypted JWT can read all of the
claims and likewise, anyone with the decryption key receiving an encrypted JWT
can also read all of the claims.

This document describes a format for signed JWTs that supports selective
disclosure (SD-JWT), enabling sharing only a subset of the claims included in
the original signed JWT instead of releasing all the claims to every verifier.
During issuance, an SD-JWT is sent from the issuer to the holder alongside an
II-Disclosures object, a JSON object that contains the mapping
between raw claim values contained in the SD-JWT and the salts for each claim
value.

This document also defines a format for HS-Disclosures JWT, which convey
a subset of the claim values of an SD-JWT to the verifier. For presentation, the
holder creates a HS-Disclosures JWT and sends it together with the SD-JWT to the
verifier. To verify claim values received in HS-Disclosures JWT, the verifier uses the
salts values in the HS-Disclosures JWT to compute the digests of the claim values and
compare them to the ones in the SD-JWT.

One of the common use cases of a signed JWT is representing a user's identity
created by an issuer. As long as the signed JWT is one-time use, it typically
only contains those claims the user has consented to disclose to a specific
verifier. However, when a signed JWT is intended to be multi-use, it needs to
contain the superset of all claims the user might want to disclose to verifiers
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

Selectively Disclosable JWT (SD-JWT)
:  A JWT [@!RFC7515] created by the issuer, which is signed as a JWS [@!RFC7515],
   that supports selective disclosure as defined in this document.

Disclosure
: A combination of the cleartext claim value, the cleartext claim name, a salt and
   optionally blinded claim name value that is used to calculate a digest for a certain claim.

Issuer-Issued Disclosures Object (II-Disclosures Object)
:  A JSON object created by the issuer that contains mapping between
   raw claim values contained in the SD-JWT and the salts for each claim value.

Holder-Selected Disclosures JWT (HS-Disclosures JWT)
:  A JWT created by the Holder that contains the Disclosures from an Issuer-Issued Disclosures Object that the Holder is disclosing to the Verifier. In addition to the Disclosures, it can contain other properties and may be signed by the Holder.

claim values of an SD-JWT in a verifiable way.

Holder binding
:  Ability of the holder to prove legitimate possession of SD-JWT by proving
   control over the same private key during the issuance and presentation. SD-JWT signed by the issuer contains
   a public key or a reference to a public key that matches to the private key controlled by the holder.

Claim name blinding
:  Feature that enables to blind not only claim values, but also claim names of the claims
that are included in SD-JWT but are not disclosed to the verifier in the HS-Disclosures JWT.

Issuer
:  An entity that creates SD-JWTs.

Holder
:  An entity that received SD-JWTs from the issuer and has control over them.

Verifier
:  An entity that requests, checks and extracts the claims from HS-Disclosures JWT.

Selective disclosure
: Process of a Holder disclosing to a Verifier a subset of claims contained in a claim set issued by an Issuer.

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
           SD-JWT and Issuer-Issued Disclosures Object
                 |
                 v
           +------------+
           |            |
           |   Holder   |
           |            |
           +------------+
                 |
              Presents
         Holder-Selected Disclosures JWT and SD-JWT
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

In the following, the contents of SD-JWTs and HS-Disclosures JWTs are described at a
conceptual level, abstracting from the data formats described afterwards.

## Creating an SD-JWT

An SD-JWT, at its core, is a digitally signed document containing digests over the claim values with random salts and other metadata.
It MUST be digitally signed using the issuer's private key.

```
SD-JWT-DOC = (METADATA, SD-CLAIMS)
SD-JWT = SD-JWT-DOC | SIG(SD-JWT-DOC, ISSUER-PRIV-KEY)
```

`SD-CLAIMS` is an object with claim names (`CLAIM-NAME`) mapped to the digests over the claim values (`CLAIM-VALUE`) with random salts (`SALT`). Digests are calculated using a digest derivation function such as a hash function, HMAC, or other (`DIGEST-DERIVATION()`):

```
SD-CLAIMS = (
    CLAIM-NAME: DIGEST-DERIVATION(SALT, CLAIM-VALUE)
)*
```

When an HMAC or another type of derivation function is used for digest calculation, a secret cryptographic key or other cryptographic secret is used instead of a salt value.
However, the term "salt" is used throughout this document for brevity.

`SD-CLAIMS` can also be nested deeper to capture more complex objects, as will be shown later.

`SD-JWT` is sent from the issuer to the holder, together with the mapping of the plain-text claim values, the salt values, and potentially some other information.

## Creating an Holder-Selected Disclosures JWT

To disclose to a verifier a subset of the SD-JWT claim values, a holder creates a JWT such as the
following:

```
HOLDER-SELECTED-DISCLOSURES-DOC = (METADATA, SD-DISCLOSURES)
HOLDER-SELECTED-DISCLOSURES-JWT = HOLDER-SELECTED-DISCLOSURES-DOC
```


`SD-DISCLOSURES` follows the structure of `SD-CLAIMS` and can be a simple object with claim names mapped to values and salts:

```
SD-DISCLOSURES = (
    CLAIM-NAME: (DISCLOSED-SALT, DISCLOSED-VALUE)
)
```

Just as `SD-CLAIMS`, `SD-DISCLOSURES` can be more complex as well.

`HOLDER-SELECTED-DISCLOSURES-JWT` is sent together with `SD-JWT` from the holder to the
verifier.

## Optional Holder Binding

Some use-cases may require holder binding.

If holder binding is desired, `SD-JWT` must contain information about key material controlled by the holder:

```
SD-JWT-DOC = (METADATA, HOLDER-PUBLIC-KEY, SD-CLAIMS)
```

Note: How the public key is included in SD-JWT is out of scope of this document. It can be passed by value or by reference.

With holder binding, the `HOLDER-SELECTED-DISCLOSURES-JWT` is signed by the holder using its private key. It therefore looks as follows:

```
HOLDER-SELECTED-DISCLOSURES = HOLDER-SELECTED-DISCLOSURES-DOC | SIG(HOLDER-SELECTED-DISCLOSURES-DOC, HOLDER-PRIV-KEY)
```

### Optional Claim Name Blinding

If claim name blinding is used, `SD-CLAIMS` is created as follows:
```
SD-CLAIMS = (
    CLAIM-NAME-PLACEHOLDER: DIGEST-DERIVATION(SALT, CLAIM-VALUE, CLAIM-NAME)
)*
```

`CLAIM-NAME-PLACEHOLDER` is a placeholder used instead of the original claim
name, chosen such that it does not leak information about the claim name (e.g.,
randomly).

The contents of `SD-DISCLOSURES` are modified as follows:
```
SD-DISCLOSURES = (
    CLAIM-NAME-PLACEHOLDER: (DISCLOSED-SALT, DISCLOSED-VALUE, DISCLOSED-CLAIM-NAME)
)
```
Note that blinded and unblinded claim names can be mixed in `SD-CLAIMS` and accordingly in `SD-DISCLOSURES`.

## Verifying an Holder-Selected Disclosures JWT

A verifier checks that

 * for each claim in `HOLDER-SELECTED-DISCLOSURES`, the digest over the disclosed values
   matches the digest under the given claim name in `SD-JWT`,
 * if holder binding is used, the `HOLDER-SELECTED-DISCLOSURES` was signed by the private key
 belonging to `HOLDER-PUBLIC-KEY`.

The detailed algorithm is described below.

# Data Formats

This section defines data formats for SD-JWT (containing digests of the salted
claim values), Issuer-Issued Disclosures (containing the mapping of the
plain-text claim values and the salt values), and HS-Disclosures
(containing a subset of the same mapping).

## The Challenge of Canonicalization

When receiving an SD-JWT with an associated Release, a verifier must be able to
re-compute digests of the disclosed claim value and, given the same input values,
obtain the same digest values as signed by the issuer.

Usually, JSON-based formats transport claim values as simple properties of a JSON object such as this:

```
...
  "family_name": "Möbius",
  "address": {
    "street_address": "Schulstr. 12",
    "locality": "Schulpforta"
  }
...
```

However, a problem arises when computation over the data need to be performed and verified, like signing or computing digests. Common signature schemes require the same byte string as input to the
signature verification as was used for creating the signature. In the digest derivation approach outlined above, the same problem exists: for the issuer and the
verifier to arrive at the same digest, the same byte string must be hashed.

JSON, however, does not prescribe a unique encoding for data, but allows for variations in the encoded string. The data above, for example, can be encoded as

```
...
"family_name": "M\u00f6bius",
"address": {
  "street_address": "Schulstr. 12",
  "locality": "Schulpforta"
}
...
```

or as

```
...
"family_name": "Möbius",
"address": {"locality":"Schulpforta", "street_address":"Schulstr. 12"}
...
```

The two representations `"M\u00f6bius"` and `"Möbius"` are very different on the byte-level, but yield
equivalent objects. Same for the representations of `address`, varying in white space and order of elements in the object.

The variations in white space, ordering of object properties, and encoding of
Unicode characters are all allowed by the JSON specification. Other variations,
e.g., concerning floating-point numbers, are described in [@RFC8785]. Variations
can be introduced whenever JSON data is serialized or deserialized and unless
dealt with, will lead to different digests and the inability to verify
signatures.

There are generally two approaches to deal with this problem:

1. Canonicalization: The data is transferred in JSON format, potentially
   introducing variations in its representation, but is transformed into a
   canonical form before computing a digest. Both the issuer and the verifier
   must use the same canonicalization algorithm to arrive at the same byte
   string for computing a digest.
2. Source string encoding: Instead of transferring data in JSON format that may
   introduce variations, the serialized data that is used as the digest input is
   transferred from the issuer to the verifier. This means that the verifier can
   easily check the digest over the byte string before deserializing the data.

Mixed approaches are conceivable, i.e., transferring both the original JSON data
plus a string suitable for computing a digest, but such approaches can easily lead to
undetected inconsistencies resulting in time-of-check-time-of-use type security
vulnerabilities.

In this specification, the source string encoding approach is used, as it allows
for simple and reliable interoperability without the requirement for a
canonicalization library. To encode the source string, JSON itself is used. This
approach means that SD-JWTs can be implemented purely based on widely available
JSON encoding and decoding libraries without the need for a custom data format
for encoding data.

To produce a source string to compute a digest, the data is put into a JSON object
together with the salt value, like so (non-normative example, see
(#sd_digests_claim) for details):

```
{"s": "6qMQvRL5haj", "v": "Möbius"}
```

Or, for the address example above:
```
{"s": "al1N3Zom221", "v":
  {"locality": "Schulpforta", "street_address": "Schulstr. 12"}}
```
(Line break and indentation of the second line for presentation only!)

This object is then JSON-encoded and used as the source string. The JSON-encoded value is transferred in the HS-Disclosures instead of the original JSON data:

```
"family_name": "{\"s\": \"6qMQvRL5haj\", \"v\": \"M\\u00f6bius\"}"
```

Or, for the address example:
```
"address": "{\"s\": \"al1N3Zom221\", \"v\":
  {\"locality\": \"Schulpforta\",
  \"street_address\": \"Schulstr. 12\"}}"
```
(Line break and indentation of the second and third line for presentation only!)

A verifier can then easily check the digest over the source string before
extracting the original JSON data. Variations in the encoding of the source
string are implicitly tolerated by the verifier, as the digest is computed over a
predefined byte string and not over a JSON object.

Since the encoding is based on JSON, all value types that are allowed in JSON
are also allowed in the `v` property in the source string. This includes
numbers, strings, booleans, arrays, and objects.

It is important to note that the HS-Disclosures containing the source string is
neither intended nor suitable for direct consumption by an application that
needs to access the disclosed claim values. The SD-JWT-Release are only intended
to be used by a verifier to check the digests over the source strings and to extract
the original JSON data. The original JSON data is then used by the application.
See (#processing_model) for details.

## Format of an SD-JWT

An SD-JWT is a JWT that MUST be signed using the issuer's private key. The
payload of an SD-JWT MUST contain the `sd_digests` and `sd_digest_derivation_alg` claims
described in the following, and MAY contain a holder's public key or a reference
thereto, as well as further claims such as `iss`, `iat`, etc. as defined or
required by the application using SD-JWTs.

### `sd_digests` Claim (Digests of Selectively Disclosable Claims) {#sd_digests_claim}

The property `sd_digests` MUST be used by the issuer to include digests of the salted claim values for any claim that is intended to be selectively disclosable.

The issuer MUST choose a cryptographically random salt value
for each claim value. The salt value MUST then be encoded as a string. It is
RECOMMENDED to base64url-encode the salt value.

The issuer MUST generate the digests over a JSON literal according to
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

The `sd_digests` claim contains an object where claim names are mapped to the
respective digests. If a claim name is to be blinded, the digests MUST contain
the `n` key as described above and the claim name in `sd_digests` MUST be
replaced by a placeholder value that does not leak information about the claim's original name. The same placeholder value is to be used in the II-Disclosures and HS-Disclosures described below.

#### Flat and Structured `sd_digests` objects

The `sd_digests` object can be a 'flat' object, directly containing all claim
names and digests without any deeper structure. The `sd_digests`
object can also be a 'structured' object, where some claims and their respective
digests are contained in places deeper in the structure. It is at the issuer's
discretion whether to use a 'flat' or 'structured' `sd_digests` SD-JWT object,
and how to structure it such that it is suitable for the use case.

Example 1 below is a non-normative example of an SD-JWT using a 'flat'
`sd_digests` object and Example 2a in the appendix shows a non-normative example
of an SD-JWT using a 'structured' `sd_digests` object. The difference between
the examples is how the `address` claim is disclosed.

Appendix 2 shows a more complex example using claims from eKYC (todo:
reference).

### Digest Derivation Function Claim

The claim `sd_digest_derivation_alg` indicates the digest derivation algorithm
used by the Issuer to generate the digests over the salts and the
claim values.

The digest derivation algorithm identifier MUST be one of the following:
- a hash algorithm value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry [IANA.Hash.Algorithms]
- an HMAC algorithm value from the "Algorithmn Name" column in the IANA "JSON Web Signature and Encryption Algorithms" registry [IANA.JWS.Algorithms]
- a value defined in another specification and/or profile of this specification

To promote interoperability, implementations MUST support the SHA-256 hash algorithm.


See (#security_considerations) for requirements regarding entropy of the salt, minimum length of the salt, and choice of a digest derivation algorithm.

### Holder Public Key Claim

If the issuer wants to enable holder binding, it MAY include a public key
associated with the holder, or a reference thereto.

It is out of the scope of this document to describe how the holder key pair is
established. For example, the holder MAY provide a key pair to the issuer,
the issuer MAY create the key pair for the holder, or
holder and issuer MAY use pre-established key material.

Note: Examples in this document use `cnf` Claim defined in [@RFC7800] to include raw public key by value in SD-JWT.

## Example 1: SD-JWT

This example and Example 2a in the appendix use the following object as the set
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
    "jwk": {
      "kty": "RSA",
      "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x656
        59kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjt
        th8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mT
        z10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wq
        f_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSG
        uxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw",
      "e": "AQAB"
    }
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "sd_digest_derivation_alg": "sha-256",
  "sd_digests": {
    "sub": "2EDXXZ1JcE6aTcM70fZopFneYAS9-hY3lalaoLuWD1s",
    "given_name": "pC56LWpTgec18Ll1kps3koXapnw6SOiI0d1ba34t-mY",
    "family_name": "EySQc316Ln3ZGJXwioELWSyylm_6OXV6rcL6LyPb7oI",
    "email": "qHv6gGaq4oFmIXyKh9ZlFjQ5rOClS-dXHiPMZyl2FaU",
    "phone_number": "jhr_PsauT4xsYZS_OxBW8y_1MLULOovKseRvF9CE0TM",
    "address": "eQXgmowqkT_ORkedoqeW0wBUy4vzkWG1VhvOjh3tl_o",
    "birthdate": "qgDxFuNpf83MkKe4GCaiLuL_XZdzO4pYD7lQKbv4zos"
  }
}
```

Important: Throughout the examples in this document, line breaks had to
be added to JSON strings and base64-encoded strings (as shown in the
next example) to adhere to the 72 character limit for lines in RFCs and
for readability. JSON does not allow line breaks in strings.

The SD-JWT is then signed by the issuer to create a document like the following:

{#example-simple-serialized_sd_jwt}
```
eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZU
kF6VmRsZnhOMjgwTmdIYUEifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N
1ZXIiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJSU0EiLCAibiI6ICJwbTRiT0hCZy1v
WWhBeVBXelI1NkFXWDNyVUlYcDExX0lDRGtHZ1M2VzNaV0x0cy1oendJM3g2NTY1OWtnN
GhWbzlkYkdvQ0pFM1pHRl9lYWV0RTMwVWhCVUVncEd3ckRyUWlKOXpxcHJtY0ZmcjNxdn
ZrR2p0dGg4WmdsMWVNMmJKY093RTdQQ0JIV1RLV1lzMTUyUjdnNkpnMk9WcGgtYThycS1
xNzlNaEtHNVFvV19tVHoxMFFUXzZINGM3UGpXRzFmamg4aHBXTm5iUF9wdjZkMXpTd1pm
YzVmbDZ5VlJMMERWMFYzbEdIS2UyV3FmX2VOR2pCckJMVmtsRFRrOC1zdFhfTVdMY1ItR
UdtWEFPdjBVQldpdFNfZFhKS0p1LXZYSnl3MTRuSFNHdXhUSUsyaHgxcHR0TWZ0OUNzdn
FpbVhLZURUVTE0cVFMMWVFN2loY3ciLCAiZSI6ICJBUUFCIn19LCAiaWF0IjogMTUxNjI
zOTAyMiwgImV4cCI6IDE1MTYyNDcwMjIsICJzZF9kaWdlc3RfZGVyaXZhdGlvbl9hbGci
OiAic2hhLTI1NiIsICJzZF9kaWdlc3RzIjogeyJzdWIiOiAiMkVEWFhaMUpjRTZhVGNNN
zBmWm9wRm5lWUFTOS1oWTNsYWxhb0x1V0QxcyIsICJnaXZlbl9uYW1lIjogInBDNTZMV3
BUZ2VjMThMbDFrcHMza29YYXBudzZTT2lJMGQxYmEzNHQtbVkiLCAiZmFtaWx5X25hbWU
iOiAiRXlTUWMzMTZMbjNaR0pYd2lvRUxXU3l5bG1fNk9YVjZyY0w2THlQYjdvSSIsICJl
bWFpbCI6ICJxSHY2Z0dhcTRvRm1JWHlLaDlabEZqUTVyT0NsUy1kWEhpUE1aeWwyRmFVI
iwgInBob25lX251bWJlciI6ICJqaHJfUHNhdVQ0eHNZWlNfT3hCVzh5XzFNTFVMT292S3
NlUnZGOUNFMFRNIiwgImFkZHJlc3MiOiAiZVFYZ21vd3FrVF9PUmtlZG9xZVcwd0JVeTR
2emtXRzFWaHZPamgzdGxfbyIsICJiaXJ0aGRhdGUiOiAicWdEeEZ1TnBmODNNa0tlNEdD
YWlMdUxfWFpkek80cFlEN2xRS2J2NHpvcyJ9fQ.0w8PQ_tg2K6Q82XhXn3-Nmi7uGeXkO
FFMSfp_8iMKRRlfg-HXXdoZWv8UECv1B2PIJITjH2RAz_egYj-dLkPopnJ-0vIDKjKhvM
CIIo0FEnTV3qQct-8s6NifR2exU1TuyF66Z9Jekk1V3M4BnKxCc6-mEf7_d1K-EfQ34dI
-6XJFh05s1_sE7ePFvLRGtj4tHHQlwWGm7wQJqPRYtA_F0N10jIlyFbw4B6T59TpI8ZjH
gucCxF9p1IUb-RYb6P1dYF4sVdQT258jAJVCAPz62JoRn-cPPwV-QbpAKD7npkk7pTxkY
g0T9_iyvMcq_RdXGqqANkJn8qxEffwp_OsgA
```


## Format of an Issuer-Issued Disclosures Object

Besides the SD-JWT itself, the holder needs to learn the raw claim values that
are contained in the SD-JWT, along with the precise input to the digest
calculation, and the salts. There MAY be other information the issuer needs to
communicate to the holder, such as a private key if the issuer selected the
holder key pair.

An Issuer-Issued Disclosures Object (II-Disclosures Object) is a JSON object containing at least the
top-level property `sd_ii_disclosures`. Its structure mirrors the one of `sd_digests` in
the SD-JWT, but the values are the inputs to the digest calculations the issuer
used, as strings.

The II-Disclosures Object MAY contain further properties, for example, to transport the holder
private key.

## Example: Issuer-Issued Disclosures Object for the Flat SD-JWT in Example 1

The II-Disclosures Object for Example 1 is as follows:

{#example-simple-iid_payload}
```json
{
  "sd_ii_disclosures": {
    "sub": "{\"s\": \"YZSmzeu7lFHUbZ8Z1QqH9Q\", \"v\":
      \"6c5c0a49-b589-431d-bae7-219122a9ec2c\"}",
    "given_name": "{\"s\": \"kHHp91-tAZt8m9E4Jl4XbQ\", \"v\":
      \"John\"}",
    "family_name": "{\"s\": \"PjIqpGWl4eB4QroDhqQw0w\", \"v\":
      \"Doe\"}",
    "email": "{\"s\": \"QRamZSB5Ky0MeJyz4EAleA\", \"v\":
      \"johndoe@example.com\"}",
    "phone_number": "{\"s\": \"xniP4JZtNWIH-Lk_Dt-o-A\", \"v\":
      \"+1-202-555-0101\"}",
    "address": "{\"s\": \"KtfsxxTm2mw0YLUcKZU8tA\", \"v\":
      {\"street_address\": \"123 Main St\", \"locality\":
      \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}}",
    "birthdate": "{\"s\": \"Ozd4wBLBwqGzJhJvTmQwdQ\", \"v\":
      \"1940-01-01\"}"
  }
}
```

Important: As described above, digests are calculated over the JSON literal
formed by serializing an object containing the salt, the claim value, and
optionally the claim name. This ensures that issuer and verifier use the same
input to their digest derivation algorithms and avoids issues with canonicalization of JSON
values that would lead to different digests. The II-Disclosures Object therefore maps claim
names to JSON-encoded arrays.

## Sending SD-JWT and Issuer-Issued Disclosures Object during Issuance

For transporting the II-Disclosures Object together with the SD-JWT from the issuer to the holder,
the II-Disclosures Object is base64url-encoded and appended to the SD-JWT using a period character `.` as the
separator.

The II-Disclosures Object and SD-JWT are implicitly linked through the digest values of the claims
in the II-Disclosures Object that is included in the SD-JWT. To ensure that the correct II-Disclosures Object and
SD-JWT pairings are being used, the holder SHOULD verify the binding between
II-Disclosures Object and SD-JWT as defined in the Verification Section of this document.

For Example 1, the combined format looks as follows:

{#example-simple-combined_sd_jwt_svc}
```
eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZU
kF6VmRsZnhOMjgwTmdIYUEifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N
1ZXIiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJSU0EiLCAibiI6ICJwbTRiT0hCZy1v
WWhBeVBXelI1NkFXWDNyVUlYcDExX0lDRGtHZ1M2VzNaV0x0cy1oendJM3g2NTY1OWtnN
GhWbzlkYkdvQ0pFM1pHRl9lYWV0RTMwVWhCVUVncEd3ckRyUWlKOXpxcHJtY0ZmcjNxdn
ZrR2p0dGg4WmdsMWVNMmJKY093RTdQQ0JIV1RLV1lzMTUyUjdnNkpnMk9WcGgtYThycS1
xNzlNaEtHNVFvV19tVHoxMFFUXzZINGM3UGpXRzFmamg4aHBXTm5iUF9wdjZkMXpTd1pm
YzVmbDZ5VlJMMERWMFYzbEdIS2UyV3FmX2VOR2pCckJMVmtsRFRrOC1zdFhfTVdMY1ItR
UdtWEFPdjBVQldpdFNfZFhKS0p1LXZYSnl3MTRuSFNHdXhUSUsyaHgxcHR0TWZ0OUNzdn
FpbVhLZURUVTE0cVFMMWVFN2loY3ciLCAiZSI6ICJBUUFCIn19LCAiaWF0IjogMTUxNjI
zOTAyMiwgImV4cCI6IDE1MTYyNDcwMjIsICJzZF9oYXNoX2FsZyI6ICJzaGEtMjU2Iiwg
InNkX2RpZ2VzdHMiOiB7InN1YiI6ICJPTWR3a2sySFB1aUluUHlwV1VXTXhvdDFZMnRTd
EdzTHVJY0RNaktkWE1VIiwgImdpdmVuX25hbWUiOiAiQWZLS0g0YTBJWmtpOE1GRHl0aE
ZhRlNfWHF6bi13UnZBTWZpeV9WallwRSIsICJmYW1pbHlfbmFtZSI6ICJlVW1YbXJ5MzJ
KaUtfNzZ4TWFzYWdrQVFRc21TVmRXNTdBamsxOHJpU0YwIiwgImVtYWlsIjogIi1SY3I0
ZkR5andsTV9pdGNNeG9RWkNFMVFBRXd5TEpjaWJFcEgxMTRLaUUiLCAicGhvbmVfbnVtY
mVyIjogIkp2Mm53MEMxd1A1QVN1dFlOQXhyV0VuYURSSXBpRjBlVFVBa1VPcDhGNlkiLC
AiYWRkcmVzcyI6ICJacmpLcy1SbUVBVmVBWVN6U3c2R1BGck1wY2djdENmYUo2dDlxUWh
iZko0IiwgImJpcnRoZGF0ZSI6ICJxWFBSUlBkcE5hZWJQOGp0YkVwTy1za0Y0bjd2N0FT
VGg4b0xnMG1rQWRRIn19.QgoJn9wkjFvM9bAr0hTDHLspuqdA21WzfBRVHkASa2ck4PFD
3TC9MiZSi3AiRytRbYT4ZzvkH3BSbm6vy68y62gj0A6OYvZ1Z60Wxho14bxZQveJZgw3u
_lMvYj6GKiUtskypFEHU-Kd-LoDVqEpf6lPQHdpsac__yQ_JL24oCEBlVQRXB-T-6ZNZf
ID6JafSkNNCYQbI8nXbzIEp1LBFm0fE8eUd4G4yPYOj1SeuR6Gy92T0vAoL5QtpIAHo49
oAmiSIj6DQNl2cNYs74jhrBIcNZyt4l8H1lV20wS5OS3T0vXaYD13fgm0p4iWD9cVg3HK
ShUVulEyrSbq94jIKg.eyJzZF9yZWxlYXNlIjogeyJzdWIiOiAie1wic1wiOiBcIjJHTE
M0MnNLUXZlQ2ZHZnJ5TlJOOXdcIiwgXCJ2XCI6IFwiNmM1YzBhNDktYjU4OS00MzFkLWJ
hZTctMjE5MTIyYTllYzJjXCJ9IiwgImdpdmVuX25hbWUiOiAie1wic1wiOiBcIjZJajd0
TS1hNWlWUEdib1M1dG12VkFcIiwgXCJ2XCI6IFwiSm9oblwifSIsICJmYW1pbHlfbmFtZ
SI6ICJ7XCJzXCI6IFwiUWdfTzY0enFBeGU0MTJhMTA4aXJvQVwiLCBcInZcIjogXCJEb2
VcIn0iLCAiZW1haWwiOiAie1wic1wiOiBcIlBjMzNKTTJMY2hjVV9sSGdndl91ZlFcIiw
gXCJ2XCI6IFwiam9obmRvZUBleGFtcGxlLmNvbVwifSIsICJwaG9uZV9udW1iZXIiOiAi
e1wic1wiOiBcImxrbHhGNWpNWWxHVFBVb3ZNTkl2Q0FcIiwgXCJ2XCI6IFwiKzEtMjAyL
TU1NS0wMTAxXCJ9IiwgImFkZHJlc3MiOiAie1wic1wiOiBcIjViUHMxSXF1Wk5hMGhrYU
Z6enpaTndcIiwgXCJ2XCI6IHtcInN0cmVldF9hZGRyZXNzXCI6IFwiMTIzIE1haW4gU3R
cIiwgXCJsb2NhbGl0eVwiOiBcIkFueXRvd25cIiwgXCJyZWdpb25cIjogXCJBbnlzdGF0
ZVwiLCBcImNvdW50cnlcIjogXCJVU1wifX0iLCAiYmlydGhkYXRlIjogIntcInNcIjogX
CJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRXCIsIFwidlwiOiBcIjE5NDAtMDEtMDFcIn0ifX
0
```

(Line breaks for presentation only.)

## Format of an Holder-Selected Disclosures JWT

HS-Disclosures JWT contains claim values and the salts of the claims that the holder
has consented to disclose to the Verifier. This enables the Verifier to verify
the claims received from the holder by computing the digests of the claim
values and the salts revealed in the HS-Disclosures JWT using the digest derivation algorithm
specified in SD-JWT and comparing them to the digests included in SD-JWT.

For each claim, an array of the salt and the claim value is contained in the
`sd_hs_disclosures` object. The structure of an `sd_hs_disclosures` object in the HS-Disclosures JWT is the same as the structure of an `sd_ii_disclosures` object in II-Disclosures Object.

The HS-Disclosures JWT MAY contain further claims, for example, to ensure a binding
to a concrete transaction (in the example the `nonce` and `aud` claims).

When the holder sends the HS-Disclosures JWT to the Verifier, the HS-Disclosures JWT MUST be a JWS
represented as the JWS Compact Serialization as described in
Section 7.1 of [@!RFC7515].

If holder binding is desired, the HS-Disclosures JWT is signed by the holder. If no
holder binding is to be used, the `none` algorithm is used, i.e., the document
is not signed. TODO: Change to plain base64 to avoid alg=none issues

## Example: Holder-Selected Disclosures JWT for Example 1

The following is a non-normative example of the contents of a HS-Disclosures JWT for Example 1:

{#example-simple-hsd_jwt_payload}
```json
{
  "nonce": "XZOUco1u_gEPknxS78sWWg",
  "aud": "https://example.com/verifier",
  "sd_hs_disclosures": {
    "given_name": "{\"s\": \"kHHp91-tAZt8m9E4Jl4XbQ\", \"v\":
      \"John\"}",
    "family_name": "{\"s\": \"PjIqpGWl4eB4QroDhqQw0w\", \"v\":
      \"Doe\"}",
    "address": "{\"s\": \"KtfsxxTm2mw0YLUcKZU8tA\", \"v\":
      {\"street_address\": \"123 Main St\", \"locality\":
      \"Anytown\", \"region\": \"Anystate\", \"country\": \"US\"}}"
  }
}
```

For each claim, a JSON literal that decodes to an object with the and the claim
value (plus optionally the claim name) is contained in the `sd_hs_disclosures` object.

Again, the HS-Disclosures JWT follows the same structure as the `sd_digests` in the SD-JWT.

Below is a non-normative example of a representation of the HS-Disclosures JWT using JWS Compact
Serialization:

{#example-simple-serialized_sd_jwt_release}
```
eyJhbGciOiAiUlMyNTYiLCAia2lkIjogIkxkeVRYd0F5ZnJpcjRfVjZORzFSYzEwVThKZ
ExZVHJFQktKaF9oNWlfclUifQ.eyJub25jZSI6ICJYWk9VY28xdV9nRVBrbnhTNzhzV1d
nIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgInNkX3JlbGVh
c2UiOiB7ImdpdmVuX25hbWUiOiAie1wic1wiOiBcIjZJajd0TS1hNWlWUEdib1M1dG12V
kFcIiwgXCJ2XCI6IFwiSm9oblwifSIsICJmYW1pbHlfbmFtZSI6ICJ7XCJzXCI6IFwiUW
dfTzY0enFBeGU0MTJhMTA4aXJvQVwiLCBcInZcIjogXCJEb2VcIn0iLCAiYWRkcmVzcyI
6ICJ7XCJzXCI6IFwiNWJQczFJcXVaTmEwaGthRnp6elpOd1wiLCBcInZcIjoge1wic3Ry
ZWV0X2FkZHJlc3NcIjogXCIxMjMgTWFpbiBTdFwiLCBcImxvY2FsaXR5XCI6IFwiQW55d
G93blwiLCBcInJlZ2lvblwiOiBcIkFueXN0YXRlXCIsIFwiY291bnRyeVwiOiBcIlVTXC
J9fSJ9fQ.fw4xRl7m1mDPCZvCTn3GOr2PgBZ--fTKfy7s-GuEifNvzW5KsJaBBFvzdZzt
m25XGhk29uw-XwEw00r0hyxXLBvWfA0XbDK3JBmdpOSW1bEyNBdSHPJoeq9Xyts2JN40v
JzU2UxNaLKDaEheWf3F_E52yhHxvMLNdvZJ9FksJdSMK6ZCyGfRJadPN2GhNltqph52sW
iFKUyUk_4RtwXmT_lF49tWOMZqtG-akN9wrBoMsleM0soA0BXIK10rG5cKZoSNr-u2luz
bdZx3CFdAenaqScIkluPPcrXBZGYyX2zYUbGQs2RRXnBmox_yl6CvLbb0qTTYhDnDEo_M
H-ZtWw
```

## Sending SD-JWT and Holder-Selected Disclosures JWT during Presentation

The SD-JWT and the HS-Disclosures JWT can be combined into one document using period character `.` as a separator (here for Example 1):

{#example-simple-combined_sd_jwt_sd_jwt_release}
```
eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZU
kF6VmRsZnhOMjgwTmdIYUEifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N
1ZXIiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJSU0EiLCAibiI6ICJwbTRiT0hCZy1v
WWhBeVBXelI1NkFXWDNyVUlYcDExX0lDRGtHZ1M2VzNaV0x0cy1oendJM3g2NTY1OWtnN
GhWbzlkYkdvQ0pFM1pHRl9lYWV0RTMwVWhCVUVncEd3ckRyUWlKOXpxcHJtY0ZmcjNxdn
ZrR2p0dGg4WmdsMWVNMmJKY093RTdQQ0JIV1RLV1lzMTUyUjdnNkpnMk9WcGgtYThycS1
xNzlNaEtHNVFvV19tVHoxMFFUXzZINGM3UGpXRzFmamg4aHBXTm5iUF9wdjZkMXpTd1pm
YzVmbDZ5VlJMMERWMFYzbEdIS2UyV3FmX2VOR2pCckJMVmtsRFRrOC1zdFhfTVdMY1ItR
UdtWEFPdjBVQldpdFNfZFhKS0p1LXZYSnl3MTRuSFNHdXhUSUsyaHgxcHR0TWZ0OUNzdn
FpbVhLZURUVTE0cVFMMWVFN2loY3ciLCAiZSI6ICJBUUFCIn19LCAiaWF0IjogMTUxNjI
zOTAyMiwgImV4cCI6IDE1MTYyNDcwMjIsICJzZF9oYXNoX2FsZyI6ICJzaGEtMjU2Iiwg
InNkX2RpZ2VzdHMiOiB7InN1YiI6ICJPTWR3a2sySFB1aUluUHlwV1VXTXhvdDFZMnRTd
EdzTHVJY0RNaktkWE1VIiwgImdpdmVuX25hbWUiOiAiQWZLS0g0YTBJWmtpOE1GRHl0aE
ZhRlNfWHF6bi13UnZBTWZpeV9WallwRSIsICJmYW1pbHlfbmFtZSI6ICJlVW1YbXJ5MzJ
KaUtfNzZ4TWFzYWdrQVFRc21TVmRXNTdBamsxOHJpU0YwIiwgImVtYWlsIjogIi1SY3I0
ZkR5andsTV9pdGNNeG9RWkNFMVFBRXd5TEpjaWJFcEgxMTRLaUUiLCAicGhvbmVfbnVtY
mVyIjogIkp2Mm53MEMxd1A1QVN1dFlOQXhyV0VuYURSSXBpRjBlVFVBa1VPcDhGNlkiLC
AiYWRkcmVzcyI6ICJacmpLcy1SbUVBVmVBWVN6U3c2R1BGck1wY2djdENmYUo2dDlxUWh
iZko0IiwgImJpcnRoZGF0ZSI6ICJxWFBSUlBkcE5hZWJQOGp0YkVwTy1za0Y0bjd2N0FT
VGg4b0xnMG1rQWRRIn19.QgoJn9wkjFvM9bAr0hTDHLspuqdA21WzfBRVHkASa2ck4PFD
3TC9MiZSi3AiRytRbYT4ZzvkH3BSbm6vy68y62gj0A6OYvZ1Z60Wxho14bxZQveJZgw3u
_lMvYj6GKiUtskypFEHU-Kd-LoDVqEpf6lPQHdpsac__yQ_JL24oCEBlVQRXB-T-6ZNZf
ID6JafSkNNCYQbI8nXbzIEp1LBFm0fE8eUd4G4yPYOj1SeuR6Gy92T0vAoL5QtpIAHo49
oAmiSIj6DQNl2cNYs74jhrBIcNZyt4l8H1lV20wS5OS3T0vXaYD13fgm0p4iWD9cVg3HK
ShUVulEyrSbq94jIKg.eyJhbGciOiAiUlMyNTYiLCAia2lkIjogIkxkeVRYd0F5ZnJpcj
RfVjZORzFSYzEwVThKZExZVHJFQktKaF9oNWlfclUifQ.eyJub25jZSI6ICJYWk9VY28x
dV9nRVBrbnhTNzhzV1dnIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3Zlcmlma
WVyIiwgInNkX3JlbGVhc2UiOiB7ImdpdmVuX25hbWUiOiAie1wic1wiOiBcIjZJajd0TS
1hNWlWUEdib1M1dG12VkFcIiwgXCJ2XCI6IFwiSm9oblwifSIsICJmYW1pbHlfbmFtZSI
6ICJ7XCJzXCI6IFwiUWdfTzY0enFBeGU0MTJhMTA4aXJvQVwiLCBcInZcIjogXCJEb2Vc
In0iLCAiYWRkcmVzcyI6ICJ7XCJzXCI6IFwiNWJQczFJcXVaTmEwaGthRnp6elpOd1wiL
CBcInZcIjoge1wic3RyZWV0X2FkZHJlc3NcIjogXCIxMjMgTWFpbiBTdFwiLCBcImxvY2
FsaXR5XCI6IFwiQW55dG93blwiLCBcInJlZ2lvblwiOiBcIkFueXN0YXRlXCIsIFwiY29
1bnRyeVwiOiBcIlVTXCJ9fSJ9fQ.fw4xRl7m1mDPCZvCTn3GOr2PgBZ--fTKfy7s-GuEi
fNvzW5KsJaBBFvzdZztm25XGhk29uw-XwEw00r0hyxXLBvWfA0XbDK3JBmdpOSW1bEyNB
dSHPJoeq9Xyts2JN40vJzU2UxNaLKDaEheWf3F_E52yhHxvMLNdvZJ9FksJdSMK6ZCyGf
RJadPN2GhNltqph52sWiFKUyUk_4RtwXmT_lF49tWOMZqtG-akN9wrBoMsleM0soA0BXI
K10rG5cKZoSNr-u2luzbdZx3CFdAenaqScIkluPPcrXBZGYyX2zYUbGQs2RRXnBmox_yl
6CvLbb0qTTYhDnDEo_MH-ZtWw
```

# Verification and Processing

## Verification by the Holder when Receiving SD-JWT and Issuer-Issued Disclosures Object

The holder SHOULD verify the binding between SD-JWT and II-Disclosures Object by performing the following steps:
 1. Check that all the claims in the II-Disclosures Object are present in the SD-JWT and that there are no claims in the SD-JWT that are not in the II-Disclosures Object
 2. Check that the digests of the claims in the II-Disclosures Object match those in the SD-JWT

## Verification by the Verifier when Receiving SD-JWT and Holder-Selected Disclosures JWT

Verifiers MUST follow [@RFC8725] for checking the SD-JWT and, if signed, the
HS-Disclosures JWT.

Verifiers MUST go through (at least) the following steps before
trusting/using any of the contents of an SD-JWT:

 1. Determine if holder binding is to be checked for the SD-JWT. Refer to (#holder_binding_security) for details.
 2. Check that the presentation consists of six period-separated (`.`) elements; if holder binding is not required, the last element can be empty.
 3. Separate the SD-JWT from the HS-Disclosures JWT.
 4. Validate the SD-JWT:
    1. Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [@RFC8725], Sections 3.1 and 3.2 for details.
    2. Validate the signature over the SD-JWT.
    3. Validate the issuer of the SD-JWT and that the signing key belongs to this issuer.
    4. Check that the SD-JWT is valid using `nbf`, `iat`, and `exp` claims, if provided in the SD-JWT.
    5. Check that the claim `sd_digests` is present in the SD-JWT.
    6. Check that the `sd_digest_derivation_alg` claim is present and its value is understand
       and the digest derivation algorithm is deemed secure.
 5. Validate the HS-Disclosures JWT:
    1. If holder binding is required, validate the signature over the SD-JWT using the same steps as for the SD-JWT plus the following steps:
      1. Determine that the public key for the private key that used to sign the HS-Disclosures JWT is bound to the SD-JWT, i.e., the SD-JWT either contains a reference to the public key or contains the public key itself.
      2. Determine that the HS-Disclosures JWT is bound to the current transaction and was created for this verifier (replay protection). This is usually achieved by a `nonce` and `aud` field within the HS-Disclosures JWT.
    2. For each claim in the HS-Disclosures JWT:
      1. Ensure that the claim is present as well in `sd_digests` in the SD-JWT.
         If `sd_digests` is structured, the claim MUST be present at the same
         place within the structure.
      2. Compute the base64url-encoded digest of the JSON literal disclosed
         by the Holder using the `sd_digest_derivation_alg` in SD-JWT.
      3. Compare the digests computed in the previous step with the one of
         the same claim in the SD-JWT. Accept the claim only when the two
         digests match.
      4. Ensure that the claim value in the HS-Disclosures JWT is a JSON-encoded
         object containing at least the keys `s` and `v`, and optionally `n`.
      5. Store the value of the key `v` as the claim value. If `n` is contained
         in the object, use the value of the key `n` as the claim name.
    3. Once all necessary claims have been verified, their values can be
       validated and used according to the requirements of the application. It
       MUST be ensured that all claims required for the application have been
       disclosured.

If any step fails, the input is not valid and processing MUST be aborted.

## Processing Model {#processing_model}

Neither an SD-JWT nor an HS-Disclosures JWT is suitable for direct use by an application.
Besides the REQUIRED verification steps listed above, it is further RECOMMENDED
that an application-consumable format is generated from the data released in
the HS-Disclosures. The RECOMMENDED way is to merge the released claims and any
plaintext claims in the SD-JWT recursively:

 * Objects from the released claims must be merged into existing objects from the SD-JWT.
 * If a key is present in both objects:
   * If the value in the released claims is and object and the value in the
     SD-JWT claims is an object, the two objects MUST be merged recursively.
   * Else, the value in the released claims MUST be used.

The keys `sd_digests` and `sd_digest_derivation_alg` SHOULD be removed prior to further
processing.

The processing is shown in Examples 2b and 3 in the Appendix.

# Security Considerations {#security_considerations}

## Mandatory digest computation of the revealed claim values by the Verifier

ToDo: add text explaining mechanisms that should be adopted to ensure that
  verifiers validate the claim values received in HS-Disclosures JWT by calculating the
  digests of those values and comparing them with the digests in the SD-JWT:
  - create a test suite that forces digest computation by the Verifiers,
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

## Entropy of the salt

The security model relies on the fact that the salt is not learned or guessed by
the attacker. It is vitally important to adhere to this principle. As such, the
salt MUST be created in such a manner that it is cryptographically random,
long enough and has high entropy that it is not practical for the attacker to
guess. A new salt MUST be chosen for each claim.

## Minimum length of the salt

The RECOMMENDED length of the randomly-generated portion of the salt is at least 128 bits.

Note that minimum 128 bits would be necessary when SHA-256, HMAC-SHA256, or a function of similar strength is used, but a smaller salt size might achieve similar level of security if a stronger iterative derivation function is used.

## Choice of a digest derivation algorithm

For the security of this scheme, the digest derivation algorithm is required to be preimage and collision
resistant, i.e., it is infeasible to calculate the salt and claim value that result in
a particular digest, and it is infeasible to find a different salt and claim value pair that
result in a matching digest, respectively.

Furthermore the hash algorithms MD2, MD4, MD5, RIPEMD-160, and SHA-1
revealed fundamental weaknesses and they MUST NOT be used.

## Holder Binding {#holder_binding_security}
TBD

## Blinding Claim Names {#blinding-claim-names}

Issuers that chose to blind claim names MUST ensure not to inadvertently leak
information about the blinded claim names to verifiers. In particular, issuers
MUST choose placeholder claim names accordingly.

It is RECOMMENDED to use cryptographically salts with at least 128 bits
of entropy as placeholder claim names.

The order of elements in JSON-encoded objects is not relevant to
applications, but the order may reveal information about the blinded
claim name to the verifier. It is therefore RECOMMENDED to ensure that
the claims in the SD-JWT, II-Disclosures object, and HS-Disclosures JWT
is shuffled or otherwise hidden, e.g., by alphabetically sorting using
the blinded claim names.

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

Furthermore, re-using the same value to blind a claim name may limit the privacy benefits.


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

## Example 2a - Structured SD-JWT
This non-normative example is based on the same claim values as Example 1, but
this time the issuer decided to create a structured object for the digests. This
allows for the disclosure of individual members of the address claim separately.

{#example-simple_structured-sd_jwt_payload}
```json
{
  "iss": "https://example.com/issuer",
  "cnf": {
    "jwk": {
      "kty": "RSA",
      "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x656
        59kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjt
        th8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mT
        z10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wq
        f_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSG
        uxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw",
      "e": "AQAB"
    }
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "sd_digest_derivation_alg": "sha-256",
  "sd_digests": {
    "sub": "p7GDm8_lnxCJUsQojBatCJQgPCZOVBGxU-eX_lUIcC4",
    "given_name": "BrmUer7nGIRyk3sbHHcZk43M9Oy_BQar0VE3NMOGk9w",
    "family_name": "8voOnlh20GGzTInd6T9-Vcu2l6Q4_Kc-keedo7_3VY8",
    "email": "b9DpmK8_xwhR4PX_MiIsQc1TyB_1NN40lI5Kj8SSNl4",
    "phone_number": "0LFRbHdtG1eze9ET1rDEtSIrPI0poCM3J0EYBt2iwVg",
    "address": {
      "street_address":
        "qYDFWJxdl_OQDdn_lxX1-E9r5H2juwqonoWM8A76X_w",
      "locality": "3mLauig0JJyjJbdMvf3jLJGSBAIt0tdvq7F_VL1gqXw",
      "region": "qRa_XKvVxCzUK8buAsxg9ylzyQlfvUgSwqATQV74z6c",
      "country": "DjbYtjTT3PAQHtVkcpvrnRboYVUfXMro6Y4oEGdHW_0"
    },
    "birthdate": "rXv8RpBXYOy9WtYf2Bg-KIdO0a3KnYGCAhL53iCsLJA"
  }
}
```

The II-Disclosures Object for this SD-JWT is as follows:

{#example-simple_structured-iid_payload}
```json
{
  "sd_ii_disclosures": {
    "sub": "{\"s\": \"2iFrkb5skOft_gSL6BhdBg\", \"v\":
      \"6c5c0a49-b589-431d-bae7-219122a9ec2c\"}",
    "given_name": "{\"s\": \"AbA1MKJ1Oyqtff2JoFKNXA\", \"v\":
      \"John\"}",
    "family_name": "{\"s\": \"vGk9hg40yrI1qazJn8qaKw\", \"v\":
      \"Doe\"}",
    "email": "{\"s\": \"6Ilb1QXTN4Qdv-1qGcQdbw\", \"v\":
      \"johndoe@example.com\"}",
    "phone_number": "{\"s\": \"-F5a6ZAOKHwUsYPDS383pQ\", \"v\":
      \"+1-202-555-0101\"}",
    "address": {
      "street_address": "{\"s\": \"t6GqrdbiTFbJYh4D38aLjA\", \"v\":
        \"123 Main St\"}",
      "locality": "{\"s\": \"B0G5ap7hsAPIYOJ21rUjgg\", \"v\":
        \"Anytown\"}",
      "region": "{\"s\": \"YTPF0rUHYtvldv1Df63WXQ\", \"v\":
        \"Anystate\"}",
      "country": "{\"s\": \"mVZ4hCTnVdpu_GN-Rb9wNw\", \"v\": \"US\"}"
    },
    "birthdate": "{\"s\": \"T6-5A3xYsyy2MnwnUWbW3w\", \"v\":
      \"1940-01-01\"}"
  }
}
```

a HS-Disclosures JWT for the SD-JWT above that discloses only `region` and `country` of
the `address` property:

{#example-simple_structured-hsd_jwt_payload}
```json
{
  "nonce": "XZOUco1u_gEPknxS78sWWg",
  "aud": "https://example.com/verifier",
  "sd_hs_disclosures": {
    "given_name": "{\"s\": \"AbA1MKJ1Oyqtff2JoFKNXA\", \"v\":
      \"John\"}",
    "family_name": "{\"s\": \"vGk9hg40yrI1qazJn8qaKw\", \"v\":
      \"Doe\"}",
    "birthdate": "{\"s\": \"T6-5A3xYsyy2MnwnUWbW3w\", \"v\":
      \"1940-01-01\"}",
    "address": {
      "region": "{\"s\": \"YTPF0rUHYtvldv1Df63WXQ\", \"v\":
        \"Anystate\"}",
      "country": "{\"s\": \"mVZ4hCTnVdpu_GN-Rb9wNw\", \"v\": \"US\"}"
    }
  }
}
```

## Example 2b - Mixing SD and Non-SD Claims

In this example, a variant of Example 2a, the issuer decided to apply selective
disclosure only to some of the claims. In particular, the `country` component of
the `address` is contained in the JWT as a regular claim, whereas the rest of
the claims can be disclosed selectively. Note that the processing model
described in (#processing_model) allows for merging the selectively disclosable
claims with the regular claims.

The JSON-payload of the SD-JWT that contains both selectively disclosable claims in the `sd_digests` object and not selectively disclosable claims in a top-level JWT claim would look as follows:

{#example-simple_structured_merging-sd_jwt_payload}
```json
{
  "iss": "https://example.com/issuer",
  "cnf": {
    "jwk": {
      "kty": "RSA",
      "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x656
        59kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjt
        th8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mT
        z10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wq
        f_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSG
        uxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw",
      "e": "AQAB"
    }
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "sd_digest_derivation_alg": "sha-256",
  "sd_digests": {
    "sub": "7HAA9WvPAYvzu3hN6OtEiGJ2du77SjwJiF6JvtbeMuU",
    "given_name": "la2htSV8whimWwbio5b05g3lsRA12jNEPAc9_HYDHy0",
    "family_name": "BpXbL49wAWVasBpaHF3JUwHwOa8VjvigCPaACogeR04",
    "email": "XrhKROmHRUGtIZ-dcBxGc63stu3xMLD3FJPRfJ98wzI",
    "phone_number": "rZBPJA86d2xPhDpSKwmlCzmtqiKPSySrV35Fn5t4HCU",
    "address": {
      "street_address":
        "xnnXv6CdbA7W32QFVR7EJR8HUSPve-BctZB8fQeQY3w",
      "locality": "oTEeEDiZ_w6RieLd-upFz3uAjhmbt_PJWCB2SmQqch8",
      "region": "IQI47wPHBkSQ6SGQrbAeCc-YfvfCtrKzOXEf76Un-JI",
      "country": "A6uzBmWsTYOHryTvu525qMsye0KjL7Ana1JAfIRqLjQ"
    },
    "birthdate": "3CT30sE4eEQH5QFeZvkUmwphHrnEwrY1DVkQ1BAIr7E"
  },
  "address": {
    "country": "US"
  }
}
```

The holder can now, for example, release the rest of the components of the `address` claim in the HS-Disclosures:


{#example-simple_structured_merging-hsd_jwt_payload}
```json
{
  "nonce": "XZOUco1u_gEPknxS78sWWg",
  "aud": "https://example.com/verifier",
  "sd_hs_disclosures": {
    "given_name": "{\"s\": \"44PE8SYm3Mg7kqxua_ftyw\", \"v\":
      \"John\"}",
    "family_name": "{\"s\": \"DBcSkeRQqVkPfTyNNWSkbA\", \"v\":
      \"Doe\"}",
    "birthdate": "{\"s\": \"nIiX9JVD9JYCPBlYcIrukA\", \"v\":
      \"1940-01-01\"}",
    "address": {
      "region": "{\"s\": \"XtnSYJPrsh_ShvklQhbDgQ\", \"v\":
        \"Anystate\"}",
      "street_address": "{\"s\": \"hP_dhW14jiTijaQZOOFvUw\", \"v\":
        \"123 Main St\"}",
      "locality": "{\"s\": \"9678ZRsZ5nwcWmU_wIqKFg\", \"v\":
        \"Anytown\"}"
    }
  }
}
```

The verifier, after verifying the SD-JWT and applying the HS-Disclosures, would
process the result according to (#processing_model) and pass the following data
to the application:


{#example-simple_structured_merging-merged}
```json
{
  "given_name": "John",
  "family_name": "Doe",
  "birthdate": "1940-01-01",
  "address": {
    "region": "Anystate",
    "street_address": "123 Main St",
    "locality": "Anytown",
    "country": "US"
  },
  "iss": "https://example.com/issuer",
  "cnf": {
    "jwk": {
      "kty": "RSA",
      "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x656
        59kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjt
        th8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mT
        z10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wq
        f_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSG
        uxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw",
      "e": "AQAB"
    }
  },
  "iat": 1516239022,
  "exp": 1516247022
}
```


## Example 3 - Complex Structured SD-JWT

In this example, a complex object such as those used for OIDC4IDA (todo reference) is used.

In this example, the Issuer is using a following object as a set of selectively disclosable claims to issue to the Holder:

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

The issuer in this example further adds the two claims `birthdate` and `place_of_birth` to the `claims` element in plain text. The following shows the resulting SD-JWT payload:

{#example-complex-sd_jwt_payload}
```json
{
  "iss": "https://example.com/issuer",
  "cnf": {
    "jwk": {
      "kty": "RSA",
      "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x656
        59kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjt
        th8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mT
        z10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wq
        f_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSG
        uxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw",
      "e": "AQAB"
    }
  },
  "iat": 1516239022,
  "exp": 1516247022,
  "sd_digest_derivation_alg": "sha-256",
  "sd_digests": {
    "verified_claims": {
      "verification": {
        "trust_framework":
          "fkIW-4iUZgTeIeDg_Z_6oFHU-wyWwazSpuaiQbc5QKw",
        "time": "VRF-G_LfTzSaYkLelVzry82l1zQxGwk1RfGcnUUWukc",
        "verification_process":
          "9OpDml4eRBM6Usfk3MF2i7kBl1xGGkzPq5Ncs1mvbPo",
        "evidence": [
          {
            "type": "HucanHhQwb-TJNg_rVpaonNSDtzPrCEebb3LfXTuLSM",
            "method": "aU7IO7ooT8vArMkqpOfkIAlKw8BNcfRyw3NXs3ZS128",
            "time": "LHcH98bV3-ZNUa00HNnqOf8W5IdijY1aEnpVzDNVBwA",
            "document": {
              "type": "3ITIlfkbUI0NveviEJBw-_VEaGiPtCDcXy9uD9orWFA",
              "issuer": {
                "name":
                  "AY7wW63Vbcd7RnKDb39sSXpLgyiVNxWgoRnV6xZD5C8",
                "country":
                  "Kd3aUmm6XHjpWp6OYiJeEZUrD5J7nIRU3SlTc-E53gs"
              },
              "number":
                "8gKpksl66fN9F2Zxs1PRPgD8kHi8dGC2JzpqtrPZavs",
              "date_of_issuance":
                "GfIEhOGWwe8J7lx6HSAPpC-Qvx0ihwWkEE0_LZ-r_DI",
              "date_of_expiry":
                "_fdljKRdp5wptGi7DwKNZEsSX6AnniVqmDE0aSznH74"
            }
          }
        ]
      },
      "claims": {
        "given_name": "sx4wGd6-ONAsiq7dN16GHeg4RAyOshRBdoXWE_E751w",
        "family_name": "Ldbea0SibAQDiZJlBigptwWXZ9QA8a0dKK7jipSn2K8",
        "nationalities":
          "tr8SXHdYS0rzAio_IhFp2lzlta4kDzKCM7hUxItCU2U",
        "address": {
          "locality": "VFgKHPXnNrZHeoBwcu61b5VCoFVX0rQjtH5aOiiLz0E",
          "postal_code":
            "G8XHi8sCPc45WATery6RSvnEcdypnrjypjBl4LBd5YE",
          "country": "YyG4Nhyfjitpo6-yMDRTARSVAnZNvkYqRY3XepoQ_j8",
          "street_address":
            "NwAKfAtjQcN_XbV3kuHt3gbUMvQ83n02C1EexI9Ro2A"
        }
      }
    },
    "birth_middle_name":
      "M5GhkvNcGjGONRey2pRORuL2yCfYz5jo0XqF6K0tUWk",
    "salutation": "8m0-sBNA8I88_LDc05C7gE31pTm_CXQfewiwlL1Sn1Y",
    "msisdn": "dLQVMDIkEHnmPVvuHNYiv7WwAqGE7mbyJMh5EfbjM1Q"
  },
  "verified_claims": {
    "claims": {
      "birthdate": "1956-01-28",
      "place_of_birth": {
        "country": "DE",
        "locality": "Musterstadt"
      }
    }
  }
}
```

The SD-JWT is then signed by the issuer to create a document like the following:

{#example-complex-serialized_sd_jwt}
```
eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZU
kF6VmRsZnhOMjgwTmdIYUEifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N
1ZXIiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJSU0EiLCAibiI6ICJwbTRiT0hCZy1v
WWhBeVBXelI1NkFXWDNyVUlYcDExX0lDRGtHZ1M2VzNaV0x0cy1oendJM3g2NTY1OWtnN
GhWbzlkYkdvQ0pFM1pHRl9lYWV0RTMwVWhCVUVncEd3ckRyUWlKOXpxcHJtY0ZmcjNxdn
ZrR2p0dGg4WmdsMWVNMmJKY093RTdQQ0JIV1RLV1lzMTUyUjdnNkpnMk9WcGgtYThycS1
xNzlNaEtHNVFvV19tVHoxMFFUXzZINGM3UGpXRzFmamg4aHBXTm5iUF9wdjZkMXpTd1pm
YzVmbDZ5VlJMMERWMFYzbEdIS2UyV3FmX2VOR2pCckJMVmtsRFRrOC1zdFhfTVdMY1ItR
UdtWEFPdjBVQldpdFNfZFhKS0p1LXZYSnl3MTRuSFNHdXhUSUsyaHgxcHR0TWZ0OUNzdn
FpbVhLZURUVTE0cVFMMWVFN2loY3ciLCAiZSI6ICJBUUFCIn19LCAiaWF0IjogMTUxNjI
zOTAyMiwgImV4cCI6IDE1MTYyNDcwMjIsICJzZF9kaWdlc3RfZGVyaXZhdGlvbl9hbGci
OiAic2hhLTI1NiIsICJzZF9kaWdlc3RzIjogeyJ2ZXJpZmllZF9jbGFpbXMiOiB7InZlc
mlmaWNhdGlvbiI6IHsidHJ1c3RfZnJhbWV3b3JrIjogImZrSVctNGlVWmdUZUllRGdfWl
82b0ZIVS13eVd3YXpTcHVhaVFiYzVRS3ciLCAidGltZSI6ICJWUkYtR19MZlR6U2FZa0x
lbFZ6cnk4MmwxelF4R3drMVJmR2NuVVVXdWtjIiwgInZlcmlmaWNhdGlvbl9wcm9jZXNz
IjogIjlPcERtbDRlUkJNNlVzZmszTUYyaTdrQmwxeEdHa3pQcTVOY3MxbXZiUG8iLCAiZ
XZpZGVuY2UiOiBbeyJ0eXBlIjogIkh1Y2FuSGhRd2ItVEpOZ19yVnBhb25OU0R0elByQ0
VlYmIzTGZYVHVMU00iLCAibWV0aG9kIjogImFVN0lPN29vVDh2QXJNa3FwT2ZrSUFsS3c
4Qk5jZlJ5dzNOWHMzWlMxMjgiLCAidGltZSI6ICJMSGNIOThiVjMtWk5VYTAwSE5ucU9m
OFc1SWRpalkxYUVucFZ6RE5WQndBIiwgImRvY3VtZW50IjogeyJ0eXBlIjogIjNJVElsZ
mtiVUkwTnZldmlFSkJ3LV9WRWFHaVB0Q0RjWHk5dUQ5b3JXRkEiLCAiaXNzdWVyIjogey
JuYW1lIjogIkFZN3dXNjNWYmNkN1JuS0RiMzlzU1hwTGd5aVZOeFdnb1JuVjZ4WkQ1Qzg
iLCAiY291bnRyeSI6ICJLZDNhVW1tNlhIanBXcDZPWWlKZUVaVXJENUo3bklSVTNTbFRj
LUU1M2dzIn0sICJudW1iZXIiOiAiOGdLcGtzbDY2Zk45RjJaeHMxUFJQZ0Q4a0hpOGRHQ
zJKenBxdHJQWmF2cyIsICJkYXRlX29mX2lzc3VhbmNlIjogIkdmSUVoT0dXd2U4SjdseD
ZIU0FQcEMtUXZ4MGlod1drRUUwX0xaLXJfREkiLCAiZGF0ZV9vZl9leHBpcnkiOiAiX2Z
kbGpLUmRwNXdwdEdpN0R3S05aRXNTWDZBbm5pVnFtREUwYVN6bkg3NCJ9fV19LCAiY2xh
aW1zIjogeyJnaXZlbl9uYW1lIjogInN4NHdHZDYtT05Bc2lxN2ROMTZHSGVnNFJBeU9za
FJCZG9YV0VfRTc1MXciLCAiZmFtaWx5X25hbWUiOiAiTGRiZWEwU2liQVFEaVpKbEJpZ3
B0d1dYWjlRQThhMGRLSzdqaXBTbjJLOCIsICJuYXRpb25hbGl0aWVzIjogInRyOFNYSGR
ZUzByekFpb19JaEZwMmx6bHRhNGtEektDTTdoVXhJdENVMlUiLCAiYWRkcmVzcyI6IHsi
bG9jYWxpdHkiOiAiVkZnS0hQWG5OclpIZW9Cd2N1NjFiNVZDb0ZWWDByUWp0SDVhT2lpT
HowRSIsICJwb3N0YWxfY29kZSI6ICJHOFhIaThzQ1BjNDVXQVRlcnk2UlN2bkVjZHlwbn
JqeXBqQmw0TEJkNVlFIiwgImNvdW50cnkiOiAiWXlHNE5oeWZqaXRwbzYteU1EUlRBUlN
WQW5aTnZrWXFSWTNYZXBvUV9qOCIsICJzdHJlZXRfYWRkcmVzcyI6ICJOd0FLZkF0alFj
Tl9YYlYza3VIdDNnYlVNdlE4M24wMkMxRWV4STlSbzJBIn19fSwgImJpcnRoX21pZGRsZ
V9uYW1lIjogIk01R2hrdk5jR2pHT05SZXkycFJPUnVMMnlDZll6NWpvMFhxRjZLMHRVV2
siLCAic2FsdXRhdGlvbiI6ICI4bTAtc0JOQThJODhfTERjMDVDN2dFMzFwVG1fQ1hRZmV
3aXdsTDFTbjFZIiwgIm1zaXNkbiI6ICJkTFFWTURJa0VIbm1QVnZ1SE5ZaXY3V3dBcUdF
N21ieUpNaDVFZmJqTTFRIn0sICJ2ZXJpZmllZF9jbGFpbXMiOiB7ImNsYWltcyI6IHsiY
mlydGhkYXRlIjogIjE5NTYtMDEtMjgiLCAicGxhY2Vfb2ZfYmlydGgiOiB7ImNvdW50cn
kiOiAiREUiLCAibG9jYWxpdHkiOiAiTXVzdGVyc3RhZHQifX19fQ.57pncJcJ6cQt2fSA
RbQLlj6e6nYMpWqHNvI2Ep45WmNGuTtI3htmodK8svpgbrT-RaLL25WF7J3CqP1ElzpZS
gVFs2VXCxGXgnTG6dQIvk2qPPfP-45hrZiMWyiwRFBr7Di68J01N90yFGbsMH5hh8kGGq
FnCpTSQwvk--6aG_03l0nGmLDjOFyauCF_Tl-SlOHzNGYoP3MOOX9jU25T8z2e3EmLVLT
a5KEmNis0GbpfSHUthbtZCCTaq-bSYaPDUHi22ZNqeoW1Y4v8nSaNIyrV9IxfPJNb37kY
N6NLn5zwI33sxE_nCd8wOxvuI0rtFtmpS_-DNgwPTnLphzUNKA
```

A HS-Disclosures JWT for some of the claims may look as follows:

{#example-complex-hsd_jwt_payload}
```json
{
  "nonce": "XZOUco1u_gEPknxS78sWWg",
  "aud": "https://example.com/verifier",
  "sd_hs_disclosures": {
    "verified_claims": {
      "verification": {
        "trust_framework": "{\"s\": \"SJKr-Pydh8RqHomXCOiVwQ\",
          \"v\": \"de_aml\"}",
        "time": "{\"s\": \"CrxH2Ez8uu2t7tEPQqwZig\", \"v\":
          \"2012-04-23T18:25Z\"}",
        "evidence": [
          {
            "type": "{\"s\": \"sPCCbZtOdjnQjfOiPBxOYA\", \"v\":
              \"document\"}"
          }
        ]
      },
      "claims": {
        "given_name": "{\"s\": \"kqwnbB6oHhaBD3F3t-KUGw\", \"v\":
          \"Max\"}",
        "family_name": "{\"s\": \"_6Do5glcgEQDMVJoPArGSA\", \"v\":
          \"Meier\"}"
      }
    }
  }
}
```

After verifying the SD-JWT and HS-Disclosures, the verifier merges the selectively
disclosed claims into the other data contained in the JWT. The verifier will
then pass the result on to the application for further processing:

{#example-complex-merged}
```json
{
  "verified_claims": {
    "verification": {
      "trust_framework": "de_aml",
      "time": "2012-04-23T18:25Z",
      "evidence": [
        {
          "type": "document"
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
      }
    }
  },
  "iss": "https://example.com/issuer",
  "cnf": {
    "jwk": {
      "kty": "RSA",
      "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x656
        59kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjt
        th8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mT
        z10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wq
        f_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSG
        uxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw",
      "e": "AQAB"
    }
  },
  "iat": 1516239022,
  "exp": 1516247022
}
```

## Example 4 - W3C Verifiable Credentials Data Model

This example illustrates how the artifacts defined in this specification can be
represented using W3C Verifiable Credentials Data Model as defined in
[@VC_DATA].

SD-JWT is equivalent to an issuer-signed W3C Verifiable Credential (VC). II-Disclosures Object is sent alongside a VC.

HS-Disclosures JWT is equivalent to a holder-signed W3C Verifiable Presentation (VP).

HS-Disclosures JWT as a VP contains a `verifiableCredential` claim inside a `vp` claim that is a string array of an SD-JWT as a VC using JWT compact serialization.

Below is a non-normative example of an SD-JWT represented as a verifiable credential
encoded as JSON and signed as JWS compliant to [@VC_DATA].

II-Disclosures Object sent alongside this SD-JWT as a JWT-VC is same as in Example 1.

```json
{
  "sub": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCc
    d-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "jti": "http://example.edu/credentials/3732",
  "iss": "https://example.com/keys/foo.jwk",
  "nbf": 1541493724,
  "iat": 1541493724,
  "exp": 1573029723,
  "cnf": {
    "jwk": {
      "kty":"RSA",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
     4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
     tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
     QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
     SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
     w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e":"AQAB"
    }
  },
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "type": [
      "VerifiableCredential",
      "UniversityDegreeCredential"
    ],
    "credentialSubject": {
      "first_name": "Jane",
      "last_name": "Doe"
    }
  },
  "sd_digests": {
    "vc": {
      "credentialSubject": {
        "email": "ET2A1JQLF85ZpBulh6UFstGrSfR4B3KM-bjQVllhxqY",
        "phone_number": "SJnciB2DIRVA5cXBrdKoH6n45788mZyUn2rnv74
          uMVU",
        "address": "0FldqLfGnERPPVDC17od9xb4w3iRJTEQbW_Yk9AmnDw",
        "birthdate": "-L0kMgIbLXe3OEkKTUGwz_QKhjehDeofKGwoPrxLuo4"
      }
    }
  }
}
```

Below is a non-normative example of a HS-Disclosures JWT represented as a verifiable presentation
encoded as JSON and signed as a JWS compliant to [@VC_DATA].

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
      "kty":"RSA",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
     4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
     tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
     QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
     SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
     w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e":"AQAB"
    }
}.{
  "iss": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCc
    d-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
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
  "sd_hs_disclosures": {
    "email": "[\"eI8ZWm9QnKPpNPeNenHdhQ\", \"johndoe@example.com\"]",
    "phone_number": "[\"Qg_O64zqAxe412a108iroA\",
      \"+1-202-555-0101\"]",
    "address": "[\"AJx-095VPrpTtN4QMOqROA\", {\"street_address\":
      \"123 Main St\", \"locality\": \"Anytown\", \"region\":
      \"Anystate\", \"country\": \"US\"}]",
    "birthdate": "[\"Pc33JM2LchcU_lHggv_ufQ\", \"1940-01-01\"]"
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

Hiding just this claim, the SD-JWT payload shown in the following would result. Note that the claims are sorted alphabetically as described in (#blinding-claim-names).

{#example-simple_structured_some_blinded-sd_jwt_payload}
```json
{
  "cnf": {
    "jwk": {
      "e": "AQAB",
      "kty": "RSA",
      "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x656
        59kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjt
        th8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mT
        z10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wq
        f_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSG
        uxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw"
    }
  },
  "exp": 1516247022,
  "iat": 1516239022,
  "iss": "https://example.com/issuer",
  "sd_digest_derivation_alg": "sha-256",
  "sd_digests": {
    "HS4QoeE9ty-I8BZTEupSzw":
      "emp2qhunGPulOGvtgor5dFwNSasDewLqNdqXCkYl4Nw",
    "address": {
      "country": "Bktf3gG1tXbn0XObrZT53RUr_lxMLZGEguLYwCvsaIg",
      "locality": "NeWRh4B9JLRfEODwno3UOXg9Pg3gtZEo45cK9pr4eZk",
      "region": "qpgFbdX1Az4Hm_E63K3J94oMzazHLCqqFb0Damo2eFE",
      "street_address": "6Ex8b2gEeACuMal74_OBH_ROVNM7wvzjSck08EC9eSs"
    },
    "birthdate": "1IjWWzdrXEs7iXUbsahdx_-8CIJsz2bcHHH_ccwgTBg",
    "email": "gszmttjNfSw7_uL31KyJRvWgL1gHM6O3LFAzqxluWDQ",
    "family_name": "Xbz5qK4Fqg-bS_CdwQYd_7qiNS9W810mRn42-FTHMPo",
    "given_name": "asBCBSyK-B45q79qxGMe6j4MijK4lZsHHCD8O_jsDdc",
    "other_secret_club_membership_no":
      "3RP5qguZWamNuvdrFS-sqqYq_MaCIzx6Zn_bOZyE9BY",
    "phone_number": "lB98F2RApo-ifhA3lwJGdqV-PAURkstN-oHmCv4LmxA",
    "sub": "sJ88WF6Q05a2eyPnLJHXzZ8bbiQXWlXl44Nss7Ywk0E"
  }
}
```

In the II-Disclosures Object, it can be seen that the blinded claim's original name is `secret_club_membership_no`. Note that the claims are sorted alphabetically as described in (#blinding-claim-names).


{#example-simple_structured_some_blinded-iid_payload}
```json
{
  "sd_ii_disclosures": {
    "HS4QoeE9ty-I8BZTEupSzw": "{\"s\": \"iq6rolXF0SyWSsdCeaETNg\",
      \"v\": \"23\", \"n\": \"secret_club_membership_no\"}",
    "address": {
      "country": "{\"s\": \"l-6DlGlNloOsAUlBhMOt_Q\", \"v\":
        \"US\"}",
      "locality": "{\"s\": \"c6kc69Gmh04VVNPRlhOV_g\", \"v\":
        \"Anytown\"}",
      "region": "{\"s\": \"qwybxKQUee9A0mMhzGC-Pg\", \"v\":
        \"Anystate\"}",
      "street_address": "{\"s\": \"qNsw9K05ZngcEqXLEGalHA\", \"v\":
        \"123 Main St\"}"
    },
    "birthdate": "{\"s\": \"OErzfd2Gy6jw1atlcCpr6A\", \"v\":
      \"1940-01-01\"}",
    "email": "{\"s\": \"woZIMokulfwyF_do1czRaA\", \"v\":
      \"johndoe@example.com\"}",
    "family_name": "{\"s\": \"ZXPEdf3K8mtRBKDAMjEcBQ\", \"v\":
      \"Doe\"}",
    "given_name": "{\"s\": \"btsLJCwSb0B7gtVLPMjjqA\", \"v\":
      \"John\"}",
    "other_secret_club_membership_no": "{\"s\":
      \"Fj8RxKoVno-9SOVOEUoMpw\", \"v\": \"42\"}",
    "phone_number": "{\"s\": \"YJSPlYo_aenthOCkapFRTg\", \"v\":
      \"+1-202-555-0101\"}",
    "sub": "{\"s\": \"Rj94TRxr3nvOw2WKtujLSA\", \"v\":
      \"6c5c0a49-b589-431d-bae7-219122a9ec2c\"}"
  }
}
```

The verifier would learn this information via the HS-Disclosures JWT:

{#example-simple_structured_some_blinded-hsd_jwt_payload}
```json
{
  "nonce": "XZOUco1u_gEPknxS78sWWg",
  "aud": "https://example.com/verifier",
  "sd_hs_disclosures": {
    "given_name": "{\"s\": \"btsLJCwSb0B7gtVLPMjjqA\", \"v\":
      \"John\"}",
    "family_name": "{\"s\": \"ZXPEdf3K8mtRBKDAMjEcBQ\", \"v\":
      \"Doe\"}",
    "birthdate": "{\"s\": \"OErzfd2Gy6jw1atlcCpr6A\", \"v\":
      \"1940-01-01\"}",
    "address": {
      "region": "{\"s\": \"qwybxKQUee9A0mMhzGC-Pg\", \"v\":
        \"Anystate\"}",
      "country": "{\"s\": \"l-6DlGlNloOsAUlBhMOt_Q\", \"v\": \"US\"}"
    },
    "HS4QoeE9ty-I8BZTEupSzw": "{\"s\": \"iq6rolXF0SyWSsdCeaETNg\",
      \"v\": \"23\", \"n\": \"secret_club_membership_no\"}"
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
  "cnf": {
    "jwk": {
      "e": "AQAB",
      "kty": "RSA",
      "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x656
        59kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjt
        th8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mT
        z10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wq
        f_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSG
        uxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw"
    }
  },
  "exp": 1516247022,
  "iat": 1516239022,
  "iss": "https://example.com/issuer",
  "sd_digest_derivation_alg": "sha-256",
  "sd_digests": {
    "3DOgmo7w7MDZNh1Zjvmwpg":
      "OXZKGG7Ltar4vz_L7sAtWIkVXVf5r9xONFKZdyoNlco",
    "7h5XiWrUSQLrv51P2vT3cA":
      "K0oJkADnWjLY_MAZNXTN8bmHIjLNCxzCIOxwY8g1Mn8",
    "CwiB46IUgi4NydIfgGTRwg":
      "4miZg7O_JaidVJyjGiPpc4FXAMN16e1SBZfOMlYg3hQ",
    "CzQ1rNB3tQmQT-jaW-uJTw":
      "RsLvZebqpBpKp7xbIFAuhtrAx10Ry-6FKoABcbeg-Kw",
    "FhBIPKqI5uQ_EtC_tmEJbA":
      "ye5H2MwiXDx6725bILJIb46H5nfQ2MQ15ZOrYh2XxBQ",
    "address": {
      "9svqZNCeiXlGrftK3HFwaA":
        "w7K75-DbMddjAUF3gjfKGzMJGvc_WpmU1zMHyf1InLA",
      "B-TASQbeBtkkfhAiuYxK0A":
        "a6cCjb7594DQ0DVMhCHxBokV9XpxfIbkHg7kpSHkD6w",
      "K7aYuNMfU49hD36pXsXK8Q":
        "s098EJxC-8R8se_iIWRcVclkeDWkcJj-E3IqnAN4axI",
      "oVemP2NxvQ6lnWpdKSrRig":
        "cugLX_QPBOc4WBBshNt8v3Guo105CZdxfw6zxbpfwhI"
    },
    "w4Q6Tk6fSIOUc-vXKnhsUA":
      "epjL-EKkkASHtsmFiKarvu56h1B3NvjUXUXeGWm2e8g",
    "xf27CKc5bqY1ZHGI9M-bFA":
      "nNbTObOY2Zt8ViP4MgFnhCAqgFKguHOFpRa0K31lPsM"
  }
}
```

The II-Disclosures Object:
{#example-simple_structured_all_blinded-iid_payload}
```json
{
  "sd_ii_disclosures": {
    "3DOgmo7w7MDZNh1Zjvmwpg": "{\"s\": \"1-M9ZNF4mjcOxfLubDU5ZA\",
      \"v\": \"1940-01-01\", \"n\": \"birthdate\"}",
    "7h5XiWrUSQLrv51P2vT3cA": "{\"s\": \"kEHfe0_z3yvs5ejOMmfFUw\",
      \"v\": \"23\", \"n\": \"secret_club_membership_no\"}",
    "CwiB46IUgi4NydIfgGTRwg": "{\"s\": \"fBXQPXk1pMU6resslYeSNg\",
      \"v\": \"johndoe@example.com\", \"n\": \"email\"}",
    "CzQ1rNB3tQmQT-jaW-uJTw": "{\"s\": \"XybH11hq3V7XygU5oe1UNw\",
      \"v\": \"John\", \"n\": \"given_name\"}",
    "FhBIPKqI5uQ_EtC_tmEJbA": "{\"s\": \"UVjLGL6QTThMSkWdam0TFg\",
      \"v\": \"+1-202-555-0101\", \"n\": \"phone_number\"}",
    "address": {
      "9svqZNCeiXlGrftK3HFwaA": "{\"s\": \"vlt16AiJ9p72_ELiVnCXpg\",
        \"v\": \"123 Main St\", \"n\": \"street_address\"}",
      "B-TASQbeBtkkfhAiuYxK0A": "{\"s\": \"jY-IPxzZeEJISV6AV8qE_A\",
        \"v\": \"US\", \"n\": \"country\"}",
      "K7aYuNMfU49hD36pXsXK8Q": "{\"s\": \"8DWvOZT4zodsKoNzzl_aGg\",
        \"v\": \"Anytown\", \"n\": \"locality\"}",
      "oVemP2NxvQ6lnWpdKSrRig": "{\"s\": \"6e_-fQrU5cTant3X74Q1kw\",
        \"v\": \"Anystate\", \"n\": \"region\"}"
    },
    "w4Q6Tk6fSIOUc-vXKnhsUA": "{\"s\": \"pU_5H6WaSgldJX2nkbI6Hw\",
      \"v\": \"Doe\", \"n\": \"family_name\"}",
    "xf27CKc5bqY1ZHGI9M-bFA": "{\"s\": \"8_-KamhTL2yeQnrBvV1EDQ\",
      \"v\": \"6c5c0a49-b589-431d-bae7-219122a9ec2c\", \"n\":
      \"sub\"}"
  }
}
```

Here, the holder decided only to disclose a subset of the claims to the verifier:

{#example-simple_structured_all_blinded-hsd_jwt_payload}
```json
{
  "nonce": "XZOUco1u_gEPknxS78sWWg",
  "aud": "https://example.com/verifier",
  "sd_hs_disclosures": {
    "CzQ1rNB3tQmQT-jaW-uJTw": "{\"s\": \"XybH11hq3V7XygU5oe1UNw\",
      \"v\": \"John\", \"n\": \"given_name\"}",
    "w4Q6Tk6fSIOUc-vXKnhsUA": "{\"s\": \"pU_5H6WaSgldJX2nkbI6Hw\",
      \"v\": \"Doe\", \"n\": \"family_name\"}",
    "3DOgmo7w7MDZNh1Zjvmwpg": "{\"s\": \"1-M9ZNF4mjcOxfLubDU5ZA\",
      \"v\": \"1940-01-01\", \"n\": \"birthdate\"}",
    "address": {
      "oVemP2NxvQ6lnWpdKSrRig": "{\"s\": \"6e_-fQrU5cTant3X74Q1kw\",
        \"v\": \"Anystate\", \"n\": \"region\"}",
      "B-TASQbeBtkkfhAiuYxK0A": "{\"s\": \"jY-IPxzZeEJISV6AV8qE_A\",
        \"v\": \"US\", \"n\": \"country\"}"
    }
  }
}
```

The verifier would decode the HS-Disclosures JWT and SD-JWT as follows:


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

   -01

   * introduce blinded claim names
   * explain why JSON-encoding of values is needed
   * explain merging algorithm ("processing model")
   * generalized hash alg to digest derivation alg which also enables HMAC to calculate digests
   * `sd_digest_derivation_alg` renamed to `sd_digest_derivation_alg`
   * Salt/Value Container (SVC) renamed to Issuer-Issued Disclosures (II-Disclosures)
   * SD-JWT-Release (SD-JWT-R) renamed to Holder-Selected Disclosures (HS-Disclosures)
   * `sd_disclosure` in II-Disclosures renamed to `sd_ii_disclosures`
   * `sd_disclosure` in HS-Disclosures renamed to `sd_hs_disclosures`
   * clarified relationship between `sd_hs_disclosure` and SD-JWT
   * updated examples
   * text clarifications
   * fix `cnf` structure in examples

   -00

   * Upload as draft-ietf-oauth-selective-disclosure-jwt-00

   [[ pre Working Group Adoption: ]]

   -02

   *  Added acknowledgements
   *  Improved Security Considerations
   *  Stressed entropy requirements for salts
   *  Python reference implementation clean-up and refactoring
   *  `hash_alg` renamed to `sd_hash_alg`

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

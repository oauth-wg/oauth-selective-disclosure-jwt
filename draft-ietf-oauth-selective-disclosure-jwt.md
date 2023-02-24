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

[[author]]
initials="B."
surname="Campbell"
fullname="Brian Campbell"
organization="Ping Identity"
    [author.address]
    email = "bcampbell@pingidentity.com"


%%%

.# Abstract

This document specifies conventions for creating JSON Web Token (JWT)
documents that support selective disclosure of JWT claims.

{mainmatter}

# Introduction {#Introduction}

The JSON-based [@!RFC8259] representation of claims in a signed JSON Web Token (JWT) [@!RFC7519] is
secured against modification using JSON Web Signature (JWS) [@!RFC7515] digital
signatures. A consumer of a signed JWT that has checked the
signature can safely assume that the contents of the token have not been
modified.  However, anyone receiving an unencrypted JWT can read all the
claims and likewise, anyone with the decryption key receiving an encrypted JWT
can also read all the claims.

One of the common use cases of a signed JWT is representing a user's
identity. As long as the signed JWT is one-time
use, it typically only contains those claims the user has consented to
disclose to a specific Verifier. However, there is an increasing number
of use cases where a signed JWT is created once and then used a number
of times by the user (the "Holder" of the JWT). In such cases, the signed JWT needs
to contain the superset of all claims the user of the
signed JWT might want to disclose to Verifiers at some point. The
ability to selectively disclose a subset of these claims depending on
the Verifier becomes crucial to ensure minimum disclosure and prevent
Verifiers from obtaining claims irrelevant for the transaction at hand.
One example of such a multi-use JWT is a verifiable credential, a
tamper-evident credential with a cryptographically verifiable authorship that
contains claims about a subject.

SD-JWTs defined in this document enable such selective disclosure of JWT claims.

Similar to the JWT specification on which it builds, this document is a product of the
Web Authorization Protocol (oauth) working group. However, while both JWT and SD-JWT
have potential OAuth 2.0 applications, their utility and application is certainly not constrained to OAuth 2.0.
JWT was developed as a general-purpose token format and has seen widespread usage in a
variety of applications. SD-JWT is a selective disclosure mechanism for JWT and is
similarly intended to be general-purpose specification.

In an SD-JWT, claims can be hidden, but cryptographically protected
against undetected modification. When issuing the SD-JWT to the Holder,
the Issuer also sends the cleartext counterparts of all hidden claims, the so-called
Disclosures, separate from the SD-JWT itself.

The Holder decides which claims to disclose to a Verifier and forwards the respective
Disclosures together with the SD-JWT to the Verifier. The Verifier
has to verify that all disclosed claim values were part of the original,
Issuer-signed SD-JWT. The Verifier will not, however, learn any claim
values not disclosed in the Disclosures.

While JWTs for claims describing natural persons are a common use case,
the mechanisms defined in this document can be used for many other use
cases as well.

This document also describes an optional mechanism for Holder Binding,
or the concept of binding an SD-JWT to key material controlled by the
Holder. The strength of the Holder Binding is conditional upon the trust
in the protection of the private key of the key pair an SD-JWT is bound to.

This specification aims to be easy to implement and to leverage
established and widely used data formats and cryptographic algorithms
wherever possible.

## Feature Summary

* This specification defines
  - a format enabling selective disclosure for JWTs,
  - formats for associated data that enables disclosing claims, and
  - formats for the combined transport of SD-JWTs and the associated data.
* The specification supports selectively disclosable claims in flat data structures
  as well as more complex, nested data structures.
* This specification enables combining selectively disclosable claims with
  clear-text claims that are always disclosed.
* For selectively disclosable claims, claim names are always blinded.


## Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they
appear in all capitals, as shown here.

**base64url** denotes the URL-safe base64 encoding without padding defined in
Section 2 of [@!RFC7515].

# Terms and Definitions

Selective disclosure:
:  Process of a Holder disclosing to a Verifier a subset of claims contained in a claim set issued by an Issuer.

Selectively Disclosable JWT (SD-JWT):
:  An Issuer-created signed JWT (JWS, [@!RFC7515])
  that supports selective disclosure as defined in this document and can contain both regular claims and digests of selectively-disclosable claims.

Disclosure:
:  A combination of a salt, a cleartext claim name, and a cleartext claim value, all of which are used to calculate a digest for the respective claim.

Cryptographic Holder Binding:
:  Ability of the Holder to prove legitimate possession of an SD-JWT by proving
  control over the same private key during the issuance and presentation. An SD-JWT with Holder Binding contains
  a public key or a reference to a public key that matches to the private key controlled by the Holder.

Issuer:
:  An entity that creates SD-JWTs.

Holder:
:  An entity that received SD-JWTs from the Issuer and has control over them.

Verifier:
:  An entity that requests, checks and extracts the claims from an SD-JWT and respective Disclosures.

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
             Issues SD-JWT
     and Issuer-Issued Disclosures
                 |
                 v
           +------------+
           |            |
           |   Holder   |
           |            |
           +------------+
                 |
           Presents SD-JWT
   and Holder-Selected Disclosures
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

This section describes SD-JWTs and Disclosures at a
conceptual level, abstracting from the data formats described in (#data_formats).

## Creating an SD-JWT

An SD-JWT, at its core, is a digitally signed document containing digests of the selectively discloseable claims (per claim: a random salt, the claim name and the claim value) with the clear-text claims as Disclosures outside the document.
An SD-JWT may also contain clear-text claims that are always disclosed to the Verifier.

Each digest value ensures the integrity of, and maps to, the respective Disclosure.  Digest values are calculated using a hash function over the Disclosures, each of which contains the claim name, the claim value, and a random salt. The Disclosures are sent to the Holder together with the SD-JWT in the Combined Format for Issuance.

## Creating Holder-Selected Disclosures

To disclose to a Verifier a subset of the SD-JWT claim values, a Holder selects a subset of the Disclosures and sends them to the Verifier along with the SD-JWT in the Combined Format for Presentation.

## Optional Holder Binding

Cryptographic Holder Binding is an optional feature, but when required by thee use-case, the SD-JWT must contain information about key material controlled by the Holder.

Note: How the public key is included in SD-JWT is out of scope of this document. It can be passed by value or by reference.

The Holder can then create a signed document, the Holder Binding JWT, using its private key. This document contains some
data provided by the Verifier (out of scope of this document) to ensure the freshness of the signature, for example, a nonce and an indicator of the
intended audience for the document.

The Holder Binding JWT is included in the Combined Format for Presentation and sent to the Verifier along with the SD-JWT and the Holder-Selected Disclosures.

Note that there may be other ways to send the Holder Binding JWT to the Verifier or to prove Holder Binding. In these cases, inclusion of the Holder Binding JWT in the Combined Format for Presentation is not required.

## Verifying Holder-Selected Disclosures

At a high level, the Verifier

 * receives the Combined Format for Presentation from the Holder and verifies the signature of the SD-JWT using the Issuer's public key,
 * verifies the Holder Binding JWT, if Holder Binding is required by the Verifier's policy, using the public key included in the SD-JWT,
 * calculates the digests over the Holder-Selected Disclosures and verifies that each digest is contained in the SD-JWT.

The detailed algorithm is described in (#verifier_verification).

# Data Formats {#data_formats}

This section defines data formats for SD-JWTs, Disclosures, Holder Binding JWTs and formats for combining these elements for transport.

## Format of an SD-JWT

An SD-JWT is a JWT that MUST be signed using the Issuer's private key. The
payload of an SD-JWT MUST contain the `_sd_alg` claim
described in the following, MAY contain one or more selectively disclosable claims, and MAY contain a Holder's public key or a reference
thereto, as well as further claims such as `iss`, `iat`, etc. as defined or
required by the application using SD-JWTs.

### Selectively Disclosable Claims {#disclosable_claims}

For each claim that is to be selectively disclosed, the Issuer creates a Disclosure, hashes it, and includes the hash instead of the original claim in the SD-JWT, as described next. The Disclosures are then sent to the Holder.

#### Creating Disclosures {#creating_disclosures}
The Issuer MUST create a Disclosure for each selectively disclosable claim as follows:

 * Create an array of three elements in this order:
   1. A salt value. See (#salt-entropy) and (#salt_minlength) for security considerations. The salt value MUST be unique for each claim that is to be selectively disclosed. It is RECOMMENDED to base64url-encode the salt value, producing a string. Any other type that is allowed in JSON MAY be used, e.g., a number. The Issuer MUST NOT disclose the salt value to any party other than the Holder.
   2. The claim name, or key, as it would be used in a regular JWT body. This MUST be a string.
   3. The claim's value, as it would be used in a regular JWT body. The value MAY be of any type that is allowed in JSON, including numbers, strings, booleans, arrays, and objects.
 * JSON-encode the array such that an UTF-8 string is produced.
 * base64url-encode the byte representation of the UTF-8 string, producing a US-ASCII [@RFC0020] string. This string is the Disclosure.

The order is decided based on the readability considerations: salts would have a constant length within the SD-JWT, claim names would be around the same length all the time, and claim values would vary in size, potentially being large objects.

The following example illustrates the steps described above.

The array is created as follows:
```json
["_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius"]
```

The resulting Disclosure would be: `WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0`

Note that the JSON encoding of the object is not canonicalized, so variations in white space, encoding
of Unicode characters, and ordering of object properties are allowed. For example, the following strings
are all valid and encode the same claim value:

 * A different way to encode the umlaut (two dots `¨` placed over the letter): `WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNXHUwMGY2Yml1cyJd`
 * No white space: `WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd`
 * Newline characters between elements: `WwoiXzI2YmM0TFQtYWM2cTJLSTZjQlc1ZXMiLAoiZmFtaWx5X25hbWUiLAoiTcO2Yml1cyIKXQ`

See (#disclosure_format_considerations) for some further considerations on the Disclosure format approach.

#### Hashing Disclosures {#hashing_disclosures}

For embedding the Disclosures in the SD-JWT, the Disclosures are hashed using the hash algorithm specified in the `_sd_alg` claim described below. The resulting digest is then included in the SD-JWT instead of the original claim value, as described next.

The digest MUST be taken over the US-ASCII bytes of the base64url-encoded Disclosure. This follows the convention in JWS [@RFC7515] and JWE [@RFC7516]. The bytes of the digest MUST then be base64url-encoded.

It is important to note that:

 * The input to the hash function is the base64url-encoded Disclosure, not the bytes encoded by the base64url string.
 * The bytes of the output of the hash function are base64url-encoded, not the bytes making up the (often used) hex representation of the bytes of the digest.

For example, the
SHA-256 digest of the Disclosure `WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0` would be
`uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY`.

#### Decoy Digests {#decoy_digests}

An Issuer MAY add additional digests to the SD-JWT that are not associated with any claim.  The purpose of such "decoy" digests is to make it more difficult for an attacker to see the original number of claims contained in the SD-JWT. It is RECOMMENDED to create the decoy digests by hashing over a cryptographically secure random number. The bytes of the digest MUST then be base64url-encoded as above. The same digest function as for the Disclosures MUST be used.

For decoy digests, no Disclosure is sent to the Holder, i.e., the Holder will see digests that do not correspond to any Disclosure. See (#decoy_digests_privacy) for additional privacy considerations.

To ensure readability and replicability, the examples in this specification do not contain decoy digests unless explicitly stated.

#### Creating an SD-JWT {#creating_sd_jwt}

An SD-JWT is a JWT that MUST be signed using the Issuer's private key.
It MUST use a JWS asymmetric digital signature algorithm and
MUST NOT use `none` or an identifier for a symmetric algorithm (MAC).

An SD-JWT MAY contain both selectively disclosable claims and non-selectively disclosable claims, i.e., claims that are always contained in the SD-JWT in plaintext and are always visible to a Verifier.

It is the Issuer who decides which claims are selectively disclosable and which are not. However, claims controlling the validity of the SD-JWT, such as `iss`, `exp`, or `nbf` are usually included in plaintext. End-User claims MAY be included as plaintext as well, e.g., if hiding the particular claims from the Verifier does not make sense in the intended use case.

Claims that are not selectively disclosable are included in the SD-JWT in plaintext just as they would be in any other JWT.

Selectively disclosable claims are omitted from the SD-JWT. Instead, the digests of the respective Disclosures and potentially decoy digests are contained as an array in a new JWT claim, `_sd`.

The `_sd` claim MUST be an array of strings, each string being a digest of a Disclosure or a decoy digest as described above.

The array MAY be empty in case the Issuer decided not to selectively disclose any of the claims at that level. However, it is RECOMMENDED to omit `_sd` claim in this case to save space.

The Issuer MUST hide the original order of the claims in the array. To ensure this, it is RECOMMENDED to shuffle the array of hashes, e.g., by sorting it alphanumerically or randomly. The precise method does not matter as long as it does not depend on the original order of elements.

Issuers MUST NOT issue SD-JWTs where

 * the key `_sd` is already used for the purpose other than to contain the array of digests, or
 * the claim value contained in a Disclosure contains (at the top level or nested deeper) an object with an `_sd` key, or
 * the same Disclosure value appears more than once (in the same array or in different arrays).


#### Nested Data in SD-JWTs {#nested_data}

Just like any JWT, an SD-JWT MAY contain key value pairs where the value is an object. For any object in an SD-JWT, the Issuer MAY decide to either make the entire object selectively disclosable or to make its properties selectively disclosable individually. In the latter case, the Issuer MAY even choose to make some of the object's properties selectively disclosable and others not.

In any case, the `_sd` claim MUST be included in the SD-JWT at the same level as the original claim and therefore MAY appear multiple times in an SD-JWT.

The following examples show some of the options an Issuer has when producing an SD-JWT with the following End-User data.

<{{examples/address_only_flat/user_claims.json}}

Important: Throughout the examples in this document, line breaks had to
be added to JSON strings and base64-encoded strings (as shown in the
next example) to adhere to the 72 character limit for lines in RFCs and
for readability. JSON does not allow line breaks in strings.

##### Option 1: Flat SD-JWT

The Issuer can decide to treat the `address` claim as a block that can either be disclosed completely or not at all. The following example shows that in this case, the entire `address` claim is treated as an object in the Disclosure.

<{{examples/address_only_flat/sd_jwt_payload.json}}

The Issuer would create the following Disclosure:

{{examples/address_only_flat/disclosures.md}}

##### Option 2: Structured SD-JWT

The Issuer may instead decide to make the `address` claim contents selectively disclosable individually:

<{{examples/address_only_structured/sd_jwt_payload.json}}

In this case, the Issuer would use the following data in the Disclosures for the `address` sub-claims:

{{examples/address_only_structured/disclosures.md}}

##### Option 3: Structured SD-JWT, only some properties selectively disclosable

The Issuer may also make one sub-claim of `address` non-selectively disclosable and hide only the other sub-claims:

<{{examples/address_only_structured_one_open/sd_jwt_payload.json}}

In this case, the Issuer would issue the following Disclosures:

{{examples/address_only_structured_one_open/disclosures.md}}

### Hash Function Claim {#hash_function_claim}

The claim `_sd_alg` indicates the hash algorithm
used by the Issuer to generate the digests over the salts and the
claim values.

The hash algorithm identifier MUST be a hash algorithm value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry [@IANA.Hash.Algorithms]
or a value defined in another specification and/or profile of this specification.

To promote interoperability, implementations MUST support the SHA-256 hash algorithm.

See (#security_considerations) for requirements regarding entropy of the salt, minimum length of the salt, and choice of a hash algorithm.

### Holder Public Key Claim {#holder_public_key_claim}

If the Issuer wants to enable Holder Binding, it MAY include a public key
associated with the Holder, or a reference thereto.

It is out of the scope of this document to describe how the Holder key pair is
established. For example, the Holder MAY provide a key pair to the Issuer,
the Issuer MAY create the key pair for the Holder, or
Holder and Issuer MAY use pre-established key material.

Note: Examples in this document use `cnf` Claim defined in [@RFC7800] to include raw public key by value in SD-JWT.

## Example 1: SD-JWT {#example-1}

This example uses the following object as the set of claims that the Issuer is issuing:

<{{examples/simple/user_claims.json}}

The following non-normative example shows the payload of an SD-JWT. The Issuer
is using a flat structure in this case, i.e., all of the claims in the `address` claim can only
be disclosed in full.

<{{examples/simple/sd_jwt_payload.json}}

The SD-JWT is then signed by the Issuer to create a JWT like the following:

<{{examples/simple/sd_jwt_serialized.txt}}

The Issuer creates the following Disclosures:

{{examples/simple/disclosures.md}}


## Combined Format for Issuance

Besides the SD-JWT itself, the Holder needs to learn the raw claim values that
are contained in the SD-JWT, along with the precise input to the digest
calculation and the salts. To this end, the Issuer sends the Disclosure objects
that were also used for the hash calculation, as described in (#creating_disclosures),
to the Holder.

The data format for sending the SD-JWT and the Disclosures to the Holder is
as follows:

```
<SD-JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>
```
This is called the Combined Format for Issuance.

The Disclosures and SD-JWT are implicitly linked through the
digest values of the Disclosures included in the SD-JWT.

### Example

For Example 1, the Combined Format for Issuance looks as follows:

<{{examples/simple/combined_issuance.txt}}

(Line breaks for presentation only.)

## Combined Format for Presentation

For presentation to a Verifier, the Holder sends the SD-JWT and a selected
subset of the Disclosures to the Verifier.

The data format for sending the SD-JWT and the Disclosures to the Verifier is
as follows (line break added for readability):

```
<SD-JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure M>~<optional Holder Binding JWT>
```
This is called the Combined Format for Presentation.

The Holder MAY send any subset of the Disclosures to the Verifier, i.e.,
none, multiple, or all Disclosures. For data that the Holder does not want to reveal
to the Verifier, the Holder MUST NOT send Disclosures or reveal the salt values in any
other way.

A Holder MUST NOT send a Disclosure that was not included in the SD-JWT or send
a Disclosure more than once.

### Enabling Holder Binding {#enabling_holder_binding}

The Holder MAY add an optional JWT to prove Holder Binding to the Verifier.
The precise contents of the JWT are out of scope of this specification.
Usually, a `nonce` and `aud` claim are included to show that the proof is
intended for the Verifier and to prevent replay attacks. How the `nonce` or
other claims are obtained by the Holder is out of scope of this specification.

Example Holder Binding JWT payload:

<{{examples/simple/hb_jwt_payload.json}}

Which is then signed by the Holder to create a JWT like the following:

<{{examples/simple/hb_jwt_serialized.txt}}

Whether to require Holder Binding is up to the Verifier's policy,
based on the set of trust requirements such as trust frameworks it belongs to.

Other ways of proving Holder Binding MAY be used when supported by the Verifier,
e.g., when the Combined Format for Presentation is itself embedded in a
signed JWT. See (#enveloping) for details.

If no Holder Binding JWT is included, the Combined Format for Presentation ends with
the `~` character after the last Disclosure.

### Example

The following is a non-normative example of the contents of a Presentation for Example 1, disclosing
the claims `given_name`, `family_name`, and `address`, as it would be sent from the Holder to the Verifier. The Holder Binding JWT as shown before is included as the last element.

<{{examples/simple/combined_presentation.txt}}

# Verification and Processing

## Processing by the Holder  {#holder_verification}

The Holder MUST perform the following (or equivalent) steps when receiving
a Combined Format for Issuance:

 1. Separate the SD-JWT and the Disclosures in the Combined Format for Issuance.
 2. Hash all of the Disclosures separately.
 3. Find the places in the SD-JWT where the digests of the Disclosures are
    included. If any of the digests cannot be found in the SD-JWT, the
    Holder MUST reject the SD-JWT.
 4. Decode Disclosures and obtain plaintext of the claim values.

It is up to the Holder how to maintain the mapping between the Disclosures and the plaintext claim values to be able to display them to the End-User when needed.

For presentation to a Verifier, the Holder MUST perform the following (or equivalent) steps:

 1. Decide which Disclosures to release to the Verifier, obtaining proper End-User consent if necessary.
 2. If Holder Binding is required, create a Holder Binding JWT.
 3. Create the Combined Format for Presentation, including the selected Disclosures and, if applicable, the Holder Binding JWT.
 4. Send the Presentation to the Verifier.

## Verification by the Verifier  {#verifier_verification}

Upon receiving a Presentation, Verifiers MUST ensure that

 * the SD-JWT is valid, i.e., it is signed by the Issuer and the signature is valid,
 * all Disclosures are correct, i.e., their digests are referenced in the SD-JWT, and
 * if Holder Binding is required, the Holder Binding JWT is signed by the Holder and valid.

To this end, Verifiers MUST follow the following steps (or equivalent):

 1. Determine if Holder Binding is to be checked according to the Verifier's policy
    for the use case at hand. This decision MUST NOT be based on whether
    a Holder Binding JWT is provided by the Holder or not. Refer to (#holder_binding_security) for
    details.
 2. Separate the Presentation into the SD-JWT, the Disclosures (if any), and the Holder Binding JWT (if provided).
 3. Validate the SD-JWT:
    1. Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [@RFC8725], Sections 3.1 and 3.2 for details. The `none` algorithm MUST NOT be accepted.
    2. Validate the signature over the SD-JWT.
    3. Validate the Issuer of the SD-JWT and that the signing key belongs to this Issuer.
    4. Check that the SD-JWT is valid using `nbf`, `iat`, and `exp` claims, if provided in the SD-JWT, and not selectively disclosed.
    5. Check that the `_sd_alg` claim is present and its value is understood and the hash algorithm is deemed secure.
 4. Create a copy of the SD-JWT payload, if required for further processing.
 5. Process the Disclosures. For each Disclosure provided:
    1. Calculate the digest over the base64url string as described in (#hashing_disclosures).
    2. Find all `_sd` keys in the SD-JWT payload that contain a digest calculated in the previous step. Note that there might be more than one `_sd` arrays in on SD-JWT.
       1. If the digest cannot be found in the SD-JWT payload, the Verifier MUST reject the Presentation.
       2. If there is more than one place where the digest is included, the Verifier MUST reject the Presentation.
       3. If there is a key `_sd` that does not refer to an array, the Verifier MUST reject the Presentation.
       4. Otherwise, insert, at the level of the `_sd` claim, the claim described by the Disclosure with the claim name and claim value provided in the Disclosure.
          1. If the Disclosure is not a JSON-encoded array of three elements, the Verifier MUST reject the Presentation.
          2. If the claim name already exists at the same level, the Verifier MUST reject the Presentation. Note that this also means that if a Holder sends the same Disclosure multiple times, the Verifier MUST reject the Presentation.
          3. If the claim value contains an object with an `_sd` key (at the top level or nested deeper), the Verifier MUST reject the Presentation.
    3. Remove all `_sd` claims from the SD-JWT payload.
    4. Remove the claim `_sd_alg` from the SD-JWT payload.
 6. If Holder Binding is required:
    1. If Holder Binding is provided by means not defined in this specification, verify the Holder Binding according to the method used.
    2. Otherwise, verify the Holder Binding JWT as follows:
       1. If Holder Binding JWT is not provided, the Verifier MUST reject the Presentation.
       2. Determine the public key for the Holder from the SD-JWT.
       3. Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [@RFC8725], Sections 3.1 and 3.2 for details. The `none` algorithm MUST NOT be accepted.
       4. Validate the signature over the Holder Binding JWT.
       5. Check that the Holder Binding JWT is valid using `nbf`, `iat`, and `exp` claims, if provided in the Holder Binding JWT.
       6. Determine that the Holder Binding JWT is bound to the current transaction and was created for this Verifier (replay protection). This is usually achieved by a `nonce` and `aud` field within the Holder Binding JWT.

If any step fails, the Presentation is not valid and processing MUST be aborted.

Otherwise, the processed SD-JWT payload can be passed to the application to be used for the intended purpose.

# Enveloping the Combined Format for Issuance and Presentation {#enveloping}

In some applications or transport protocols, it is desirable to put an SD-JWT and associated Disclosures into a JWT container. For example, an implementation may envelope all credentials and presentations, independent of their format, in a JWT to enable application-layer encryption during transport.

For such use cases, the SD-JWT and the respective Disclosures SHOULD be transported as a single string using the Combined Formats for Issuance and Presentation, respectively. Holder Binding MAY be achieved by signing the envelope JWT instead of adding a separate Holder Binding JWT as described in (#enabling_holder_binding).

The claim `_sd_jwt` SHOULD be used when transporting a Combined Format unless the application or protocol defines a different claim name.

The following non-normative example shows a Combined Format for Presentation enveloped in a JWT payload:

```
{
  "iss": "https://holder.example.com",
  "sub": "did:example:123",
  "aud": "https://verifier.example.com",
  "exp": 1590000000,
  "iat": 1580000000,
  "nbf": 1580000000,
  "jti": "urn:uuid:12345678-1234-1234-1234-123456789012",
  "_sd_jwt": "eyJhbGci...emhlaUJhZzBZ~eyJhb...dYALCGg~"
}
```

Here, `eyJhbGci...emhlaUJhZzBZ` represents the SD-JWT and `eyJhb...dYALCGg` represents a Disclosure. The Combined Format for Presentation does not contain a Holder Binding JWT as the outer container can be signed instead.

# Security Considerations {#security_considerations}

## Mandatory digest computation of the revealed claim values by the Verifier

ToDo: add text explaining mechanisms that should be adopted to ensure that
  Verifiers validate the claim values received in HS-Disclosures JWT by calculating the
  digests of those values and comparing them with the digests in the SD-JWT:
  - create a test suite that forces digest computation by the Verifiers,
    and includes negative test cases in test vectors
  - use only implementations/libraries that are compliant to the test suite
  - etc.

## Mandatory signing of the SD-JWT

The SD-JWT MUST be signed by the Issuer to protect integrity of the issued
claims. An attacker can modify or add claims if an SD-JWT is not signed (e.g.,
change the "email" attribute to take over the victim's account or add an
attribute indicating a fake academic qualification).

The Verifier MUST always check the SD-JWT signature to ensure that the SD-JWT
has not been tampered with since its issuance. If the signature on the SD-JWT
cannot be verified, the SD-JWT MUST be rejected.

## Manipulation of Disclosures

Holders can manipulate the Disclosures by changing the values of the claims
before sending them to the Issuer. The Issuer MUST check the Disclosures to
ensure that the values of the claims are correct, i.e., the digests of the Disclosures are actually present in the signed SD-JWT.

A naive Verifier that extracts
all claim values from the Disclosures (without checking the hashes) and inserts them into the SD-JWT payload
is vulnerable to this attack. However, in a structured SD-JWT, without comparing the digests of the
Disclosures, such an implementation could not determine the correct place in a
nested object where a claim needs to be inserted. Therefore, the naive implementation
would not only be insecure, but also incorrect.

The steps described in (#verifier_verification) ensure that the Verifier
checks the Disclosures correctly.

## Entropy of the salt {#salt-entropy}

The security model that conceals the plaintext claims relies on the fact
that salts not revealed to an attacker cannot be learned or guessed by
the attacker, even if other salts have been revealed. It is vitally
important to adhere to this principle. As such, each salt MUST be created
in such a manner that it is cryptographically random, long enough, and
has high entropy that it is not practical for the attacker to guess. A
new salt MUST be chosen for each claim independently from other salts.

## Minimum length of the salt {#salt_minlength}

The RECOMMENDED minimum length of the randomly-generated portion of the salt is 128 bits.


The Issuer MUST ensure that a new salt value is chosen for each claim,
including when the same claim name occurs at different places in the
structure of the SD-JWT. This can be seen in Example 3 in the Appendix,
where multiple claims with the name `type` appear, but each of them has
a different salt.

## Choice of a Hash Algorithm

For the security of this scheme, the hash algorithm is required to be preimage resistant and second-preimage
resistant, i.e., it is infeasible to calculate the salt and claim value that result in
a particular digest, and, for any salt and claim value pair, it is infeasible to find a different salt and claim value pair that
result in the same digest, respectively.

Hash algorithms that do not meet the aforementioned requirements MUST NOT be used.
Inclusion in the "Named Information Hash Algorithm" registry [@IANA.Hash.Algorithms]
alone does not indicate a hash algorithm's suitability for use in SD-JWT (it contains several
heavily truncated digests, such as `sha-256-32` and `sha-256-64`, which are unfit for security
applications).

Furthermore, the hash algorithms MD2, MD4, MD5, RIPEMD-160, and SHA-1
revealed fundamental weaknesses and they MUST NOT be used.

## Holder Binding {#holder_binding_security}
Holder binding aims to ensure that the presenter of a credential is
actually the legitimate Holder of the credential. There are, in general,
two approaches to Holder Binding: Claims-based Holder Binding and
Crpytographic Holder Binding.

Claims-based Holder Binding means that the Issuer includes claims in the
SD-JWT that a Verifier can correlate with the Holder, potentially with
the help of other credentials presented at the same time. For example,
in a vaccination certificate, the Issuer can include a claim that
contains the Holder's name and birthdate, and a Verifier can correlate
this data with the Holder's passport that has to be presented together
with the vaccination certificate - either as a digital credential or a
physical document.

Cryptographic Holder Binding means that the Issuer includes some
cryptographic data, usually a public key, belonging to the Holder. The
Holder can then sign over some data defined by the Verifier to prove
that the Holder is in possession of the private key.

Without Holder Binding, a Verifier only gets the proof that the
credential was issued by a particular Issuer, but the credential itself
can be replayed by anyone who gets access to it. This means that, for
example, after a credential was leaked to an attacker, the attacker can
present the credential to any verifier that does not require Holder
Binding. But also a malicious Verifier to which the Holder presented the
credential can present the credential to another Verifier if that other
Verifier does not require Holder Binding.

Verifiers MUST decide whether Holder Binding is required for a
particular use case or not before verifying a credential. This decision
can be informed by various factors including, but not limited to the following:
business requirements, the use case, the type of
binding between a Holder and its credential that is required for a use
case, the sensitivity of the use case, the expected properties of a
credential, the type and contents of other credentials expected to be
presented at the same time, etc.

This can be showcased based on two scenarios for a mobile driver's license use case for SD-JWT:

**Scenario A:** For the verification of the driver's license when
stopped by a police officer for exceeding a speed limit, Holder Binding may be necessary to ensure that the person
driving the car and presenting the license is the actual Holder of the
license. The Verifier (e.g., the software used by the police officer)
will ensure that a Holder Binding JWT is present and signed with the Holder's private
key. Claims-based Holder Binding may be used as well, e.g., by including a
first name, last name and a date of birth that matches that of an insurance policy paper.

**Scenario B:** A rental car agency may want to ensure, for insurance
purposes, that all drivers named on the rental contract own a
government-issued driver's license. The signer of the rental contract
can present the mobile driver's license of all named drivers. In this
case, the rental car agency does not need to check Holder Binding as the
goal is not to verify the identity of the person presenting the license,
but to verify that a license exists and is valid.

It is important that a Verifier does not make its security policy
decisions based on data that can be influenced by an attacker or that
can be misinterpreted. For this reason, when deciding whether Holder
binding is required or not, Verifiers MUST NOT take into account

 * whether an Holder Binding JWT is present or not, as an attacker can
   remove the Holder Binding JWT from any Presentation and present it to the
   Verifier, or
 * whether Holder Binding data is present in the SD-JWT or not, as the
   Issuer might have added the key to the SD-JWT in a format/claim that
   is not recognized by the Verifier.

If a Verifier has decided that Holder Binding is required for a
particular use case and the Holder Binding is not present, does not fulfill the requirements
(e.g., on the signing algorithm), or no recognized
Holder Binding data is present in the SD-JWT, the Verifier will reject the
presentation, as described in (#verifier_verification).

## Blinding Claim Names {#blinding-claim-names}

SD-JWT ensures that names of claims that are selectively disclosable are
always blinded. This prevents an attacker from learning the names of the
disclosable claims. However, the names of the claims that are not
disclosable are not blinded. This includes the keys of objects that themselves
are not blinded, but contain disclosable claims. This limitation
needs to be taken into account by Issuers when creating the structure of
the SD-JWT.

## Issuer Signature Key Distribution and Rotation {#issuer_signature_key_distribution}

This specification does not define how signature verification keys of
Issuers are distributed to Verifiers. However, it is RECOMMENDED that
Issuers publish their keys in a way that allows for efficient and secure
key rotation and revocation, for example, by publishing keys at a
predefined location using the JSON Web Key Set (JWKS) format [@RFC7517].
Verifiers need to ensure that they are not using expired or revoked keys
for signature verification using reasonable and appropriate means for the given
key-distribution method.

# Privacy Considerations {#privacy_considerations}

## Storage of Signed User Data

Wherever End-User data is stored, it represents a potential
target for an attacker. This target can be of particularly
high value when the data is signed by a trusted authority like an
official national identity service. For example, in OpenID Connect,
signed ID Tokens can be stored by Relying Parties. In the case of
SD-JWT, Holders have to store signed SD-JWTs and associated Disclosures,
and Issuers and Verifiers may decide to do so as well.

Not surprisingly, a leak of such data risks revealing private data of End-Users
to third parties. Signed End-User data, the authenticity of which
can be easily verified by third parties, further exacerbates the risk.
As discussed in (#holder_binding_security), leaked
SD-JWTs may also allow attackers to impersonate Holders unless Holder
Binding is enforced and the attacker does not have access to the
Holder's cryptographic keys. Altogether, leaked SD-JWT credentials may have
a high monetary value on black markets.

Due to these risks, systems implementing SD-JWT SHOULD be designed to
minimize the amount of data that is stored. All involved parties SHOULD
store SD-JWTs only for as long as needed, including in log files.

Issuers SHOULD NOT store SD-JWTs after issuance.

Holders SHOULD store SD-JWTs and associated Disclosures only in
encrypted form, and, wherever possible, use hardware-backed encryption
in particular for the private Holder Binding key. Decentralized storage
of data, e.g., on End-User devices, SHOULD be preferred for End-User
credentials over centralized storage. Expired SD-JWTs SHOULD be deleted
as soon as possible.

Verifiers SHOULD NOT store SD-JWTs after verification. It may be
sufficient to store the result of the verification and any End-User data
that is needed for the application.

If reliable and secure key rotation and revocation is ensured according
to (#issuer_signature_key_distribution), Issuers may MAY opt to publish
expired or revoked private signing keys (after a grace period that
ensures that the keys are not cached any longer at any Verifier). This
reduces the value of any leaked credentials as the signatures on them
can no longer be trusted to originate from the Issuer.


## Confidentiality during Transport

If the SD-JWT and associated Disclosures are transmitted over an insecure
channel during issuance or presentation, an adversary may be able to
intercept and read the End-User's personal data or correlate the information with previous uses of the same SD-JWT.

Usually, transport protocols for issuance and presentation of credentials
are designed to protect the confidentiality of the transmitted data, for
example, by requiring the use of TLS.

This specification therefore considers the confidentiality of the data to be
provided by the transport protocol and does not specify any encryption
mechanism.

Implementers MUST ensure that the transport protocol provides confidentiality,
if the privacy of End-User data or correlation attacks are a concern. Implementers MAY define an
envelope format (such as described in (#enveloping) or nesting the SD-JWT Combined Format as
the plaintext payload of a JWE) to encrypt the SD-JWT
and associated Disclosures when transmitted over an insecure channel.

## Decoy Digests {#decoy_digests_privacy}

The use of decoy digests is RECOMMENDED when the number of claims (or the existence of particular claims) can be a side-channel disclosing information about otherwise undisclosed claims. In particular, if a claim in an SD-JWT is present only if a certain condition is met (e.g., a membership number is only contained if the End-User is a member of a group), the Issuer SHOULD add decoy digests when the condition is not met.

Decoy digests increase the size of the SD-JWT. The number of decoy digests (or whether to use them at all) is a trade-off between the size of the SD-JWT and the privacy of the End-User's data.

## Unlinkability

Colluding Issuer/Verifier or Verifier/Verifier pairs could link issuance/presentation
or two presentation sessions to the same user on the basis of unique values encoded in the SD-JWT
(Issuer signature, salts, digests, etc.).

To prevent these types of linkability, various methods, including but not limited to the following ones can be used:

- Use advanced cryptographic schemes, outside the scope of this specification.
- Issue a batch of SD-JWTs to the Holder to enable the Holder to use a unique SD-JWT per Verifier. This only helps with Verifier/Verifier unlinkability.

# Acknowledgements {#Acknowledgements}

We would like to thank
Alen Horvat,
Arjan Geluk,
Christian Paquin,
David Bakker,
David Waite,
Fabian Hauck,
Giuseppe De Marco,
John Mattsson,
Matthew Miller,
Justin Richer,
Kushal Das,
Mike Jones,
Nat Sakimura,
Orie Steele,
Pieter Kasselman,
Ryosuke Abe,
Shawn Butterfield,
Torsten Lodderstedt, and
Vittorio Bertocci
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

<reference anchor="OIDC.IDA" target="https://openid.net/specs/openid-connect-4-identity-assurance-1_0-13.html">
  <front>
    <title>OpenID Connect for Identity Assurance 1.0</title>
    <author initials="T." surname="Lodderstedt" fullname="Torsten Lodderstedt">
      <organization>yes.com</organization>
    </author>
    <author initials="D." surname="Fett" fullname="Daniel Fett">
      <organization>yes.com</organization>
    </author>
    <author initials="M." surname="Haine" fullname="Mark Haine">
      <organization>Considrd.Consulting Ltd</organization>
    </author>
    <author initials="A." surname="Pulido" fullname="Alberto Pulido">
      <organization>Santander</organization>
    </author>
    <author initials="K." surname="Lehmann" fullname="Kai Lehmann">
      <organization>1&amp;1 Mail &amp; Media Development &amp; Technology GmbH</organization>
    </author>
    <author initials="K." surname="Koiwai" fullname="Kosuke Koiwai">
      <organization>KDDI Corporation</organization>
    </author>
  </front>
</reference>

<reference anchor="IANA.Hash.Algorithms" target="https://www.iana.org/assignments/named-information/named-information.xhtml">
  <front>
    <author fullname="IANA"></author>
    <title>Named Information Hash Algorithm</title>
  </front>
</reference>


<reference anchor="IANA.JWS.Algorithms" target="https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms">
  <front>
    <author fullname="IANA"></author>
    <title>JSON Web Signature and Encryption Algorithms</title>
  </front>
</reference>

{backmatter}

# Additional Examples

All of the following examples are non-normative.

## Example 2a: Handling Structured Claims {#example-simple_structured}

This example uses the following object as the set of claims that the Issuer is issuing:

<{{examples/simple_structured/user_claims.json}}

Note that in contrast to Example 1, here the Issuer decided to create a structured object for the `address` claim, allowing for separate disclosure of the individual members of the claim.

<{{examples/simple_structured/sd_jwt_payload.json}}

The Disclosures for this SD-JWT are as follows:

{{examples/simple_structured/disclosures.md}}

A Presentation for the SD-JWT that discloses only `region`
and `country` of the `address` property and without a Holder Binding JWT could look as follows:

<{{examples/simple_structured/combined_presentation.txt}}

## Example 2b: Adding Decoys {#example-simple_structured_with_decoys}

This example is based on the same set of user data as  Example 2a, but
here, the Issuer decided to add decoy digests to the SD-JWT.

The SD-JWT payload is as follows:

<{{examples/simple_structured_with_decoys/sd_jwt_payload.json}}

Since the Disclosures or Presentation are not affected by the decoy digests (other than a slightly larger SD-JWT), they are omitted here.


## Example 3 - Complex Structured SD-JWT {#example-complex-structured-sd-jwt}

In this example, an SD-JWT with a complex object is demonstrated. Here, the data
structures defined in OIDC4IDA [@OIDC.IDA] are used.

The Issuer is using the following user data:

<{{examples/complex_ekyc/user_claims.json}}

The Issuer in this example sends the two claims `birthdate` and `place_of_birth` in the `claims` element in plain text. The following shows the resulting SD-JWT payload:

<{{examples/complex_ekyc/sd_jwt_payload.json}}

With the following Disclosures:

{{examples/complex_ekyc/disclosures.md}}

The Verifier would receive the Issuer-signed SD-JWT together with a selection
of the Disclosures. The Presentation in this example would look as follows:

<{{examples/complex_ekyc/combined_presentation.txt}}

After the verification of the data, the Verifier will
pass the following result on to the application for further processing:

<{{examples/complex_ekyc/verified_contents.json}}

## Example 4 - W3C Verifiable Credentials Data Model (work in progress)

This example illustrates how the artifacts defined in this specification can be
represented using W3C Verifiable Credentials Data Model as defined in
[@VC_DATA].

SD-JWT is equivalent to an Issuer-signed W3C Verifiable Credential (W3C VC). Disclosures are sent alongside a VC.

A Presentation with a Holder Binding JWT is equivalent to a Holder-signed W3C Verifiable Presentation (W3C VP).

Holder Binding is applied and the Holder Binding JWT is signed using a raw public key passed in a `cnf` Claim in a W3C VC (SD-JWT).

Below is a non-normative example of an SD-JWT represented as a verifiable credential
encoded as JSON and signed as JWS compliant to [@VC_DATA].

The following data will be used in this example:

<{{examples/w3c-vc/user_claims.json}}

The payload of a corresponding SD-JWT looks as follows:

<{{examples/w3c-vc/sd_jwt_payload.json}}

Disclosures:

{{examples/w3c-vc/disclosures.md}}

# Disclosure Format Considerations {#disclosure_format_considerations}

As described in (#disclosable_claims), the Disclosure structure is JSON containing salt and the
cleartext content of a claim, which is base64url encoded. The encoded value is the input used to calculate
a digest for the respective claim. The inclusion of digest value in the signed JWT ensures the integrity of
the claim value. Using encoded content as the input to the integrity mechanism is conceptually similar to the
approach in JWS and particularly useful when the content, like JSON, can have differences but be semantically
equivalent. Some further discussion of the considerations around this design decision follows.

When receiving an SD-JWT with associated Disclosures, a Verifier must
be able to re-compute digests of the disclosed claim values and, given
the same input values, obtain the same digest values as signed by the
Issuer.

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
signature verification as was used for creating the signature. In the digest approach outlined above, the same problem exists: for the Issuer and the
Verifier to arrive at the same digest, the same byte string must be hashed.

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

The variations in white space, ordering of object properties, and
encoding of Unicode characters are all allowed by the JSON
specification, including further variations, e.g., concerning
floating-point numbers, as described in [@RFC8785]. Variations can be
introduced whenever JSON data is serialized or deserialized and unless
dealt with, will lead to different digests and the inability to verify
signatures.

There are generally two approaches to deal with this problem:

1. Canonicalization: The data is transferred in JSON format, potentially
   introducing variations in its representation, but is transformed into a
   canonical form before computing a digest. Both the Issuer and the Verifier
   must use the same canonicalization algorithm to arrive at the same byte
   string for computing a digest.
2. Source string hardening: Instead of transferring data in a format that
   may introduce variations, a representation of the data is serialized.
   This representation is then used as the hashing input at the Verifier,
   but also transferred to the Verifier and used for the same digest
   calculation there. This means that the Verifier can easily compute and check the
   digest of the byte string before finally deserializing and
   accessing the data.

Mixed approaches are conceivable, i.e., transferring both the original JSON data
plus a string suitable for computing a digest, but such approaches can easily lead to
undetected inconsistencies resulting in time-of-check-time-of-use type security
vulnerabilities.

In this specification, the source string hardening approach is used, as
it allows for simple and reliable interoperability without the
requirement for a canonicalization library. To harden the source string,
any serialization format that supports the necessary data types could
be used in theory, like protobuf, msgpack, or pickle. In this
specification, JSON is used and plain text values of each Disclosure are encoded using base64url-encoding
for transport. This approach means that SD-JWTs can be implemented purely based
on widely available JWT, JSON, and Base64 encoding and decoding libraries.

A Verifier can then easily check the digest over the source string before
extracting the original JSON data. Variations in the encoding of the source
string are implicitly tolerated by the Verifier, as the digest is computed over a
predefined byte string and not over a JSON object.

It is important to note that the Disclosures are neither intended nor
suitable for direct consumption by
an application that needs to access the disclosed claim values after the verification by the Verifier. The
Disclosures are only intended to be used by a Verifier to check
the digests over the source strings and to extract the original JSON
data. The original JSON data is then used by the application. See
(#verifier_verification) for details.


# Document History

   [[ To be removed from the final specification ]]

   -03

   * Discussion on holder binding and privacy of stored credentials
   * Add some context about SD-JWT being general-purpose despite being a product of the OAuth WG
   * More explicitly say that SD-JWTs have to be signed asymmetrically (no MAC and no `none`)
   * Use ES256 instead of RS256 in examples
   * Rename and move the c14n challenges section to an appendix
   * A bit more in security considerations for Choice of a Hash Algorithm (1st & 2nd preimage resistant and not majorly truncated)
   * Remove the notational figures from the Concepts section
   * Fix the Document History (which had a premature list for -03)

   -02

   * Disclosures are now delivered not as a JWT but as separate base64url-encoded JSON objects.
   * In the SD-JWT, digests are collected under a `_sd` claim per level.
   * Terms "II-Disclosures" and "HS-Disclosures" are replaced with "Disclosures".
   * Holder Binding is now separate from delivering the Disclosures and implemented, if required, with a separate JWT.
   * Examples updated and modified to properly explain the specifics of the new SD-JWT format.
   * Examples are now pulled in from the examples directory, not inlined.
   * Updated and automated the W3C VC example.
   * Added examples with multibyte characters to show that the specification and demo code work well with UTF-8.
   * reverted back to hash alg from digest derivation alg (renamed to `_sd_alg`)
   * reformatted

   -01

   * introduced blinded claim names
   * explained why JSON-encoding of values is needed
   * explained merging algorithm ("processing model")
   * generalized hash alg to digest derivation alg which also enables HMAC to calculate digests
   * `_sd_hash_alg` renamed to `sd_digest_derivation_alg`
   * Salt/Value Container (SVC) renamed to Issuer-Issued Disclosures (II-Disclosures)
   * SD-JWT-Release (SD-JWT-R) renamed to Holder-Selected Disclosures (HS-Disclosures)
   * `sd_disclosure` in II-Disclosures renamed to `sd_ii_disclosures`
   * `sd_disclosure` in HS-Disclosures renamed to `sd_hs_disclosures`
   * clarified relationship between `sd_hs_disclosure` and SD-JWT
   * clarified combined formats for issuance and presentation
   * clarified security requirements for blinded claim names
   * improved description of Holder Binding security considerations - especially around the usage of "alg=none".
   * updated examples
   * text clarifications
   * fixed `cnf` structure in examples
   * added feature summary

   -00

   * Upload as draft-ietf-oauth-selective-disclosure-jwt-00

   [[ pre Working Group Adoption: ]]

   -02

   *  Added acknowledgements
   *  Improved Security Considerations
   *  Stressed entropy requirements for salts
   *  Python reference implementation clean-up and refactoring
   *  `hash_alg` renamed to `_sd_hash_alg`

   -01

   *  Editorial fixes
   *  Added `hash_alg` claim
   *  Renamed `_sd` to `sd_digests` and `sd_release`
   *  Added descriptions on Holder Binding - more work to do
   *  Clarify that signing the SD-JWT is mandatory

   -00

   *  Renamed to SD-JWT (focus on JWT instead of JWS since signature is optional)
   *  Make Holder Binding optional
   *  Rename proof to release, since when there is no signature, the term "proof" can be misleading
   *  Improved the structure of the description
   *  Described verification steps
   *  All examples generated from python demo implementation
   *  Examples for structured objects


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

This specification defines a mechanism for selective disclosure of individual elements of a JSON object
used as the payload of a JSON Web Signature (JWS) structure.
It encompasses various applications, including but not limited to the selective disclosure of JSON Web Token (JWT) claims.

{mainmatter}

# Introduction {#Introduction}

This document specifies conventions for creating JSON Web Signature (JWS) [@!RFC7515]
structures with JSON [@!RFC8259] objects as the payload while supporting selective disclosure of individual elements of that JSON.
Because JSON Web Token (JWT) [@!RFC7519] is a very prevalent application of JWS with a JSON payload, the selective disclosure of JWT claims receives primary treatment herein. However, that does not preclude the mechanism's applicability to other or more general applications of JWS with JSON payloads.

The JSON-based representation of claims in a signed JWT is
secured against modification using JWS digital
signatures. A consumer of a signed JWT that has checked the
signature can safely assume that the contents of the token have not been
modified.  However, anyone receiving an unencrypted JWT can read all the
claims. Likewise, anyone with the decryption key receiving encrypted JWT
can also read all the claims.

One of the common use cases of a signed JWT is representing a user's
identity. As long as the signed JWT is one-time
use, it typically only contains those claims the user has consented to
disclose to a specific Verifier. However, there is an increasing number
of use cases where a signed JWT is created once and then used a number
of times by the user (the "Holder" of the JWT). In such use cases, the signed JWT needs
to contain the superset of all claims the user of the
signed JWT might want to disclose to Verifiers at some point. The
ability to selectively disclose a subset of these claims depending on
the Verifier becomes crucial to ensure minimum disclosure and prevent
Verifiers from obtaining claims irrelevant for the transaction at hand.
SD-JWTs defined in this document enable such selective disclosure of JWT claims.

One example of a multi-use JWT is a verifiable credential, an Issuer-signed
credential that contains the claims about a subject, and whose authenticity can be
cryptographically verified.

Similar to the JWT specification on which it builds, this document is a product of the
Web Authorization Protocol (oauth) working group. However, while both JWT and SD-JWT
have potential OAuth 2.0 applications, their utility and application is certainly not constrained to OAuth 2.0.
JWT was developed as a general-purpose token format and has seen widespread usage in a
variety of applications. SD-JWT is a selective disclosure mechanism for JWT and is
similarly intended to be general-purpose specification.

While JWTs with claims describing natural persons are a common use case, the
mechanisms defined in this document can be used for other use cases as well.

In an SD-JWT, claims can be hidden, but cryptographically
protected against undetected modification. "Claims" here refers to both
object properties (key-value pairs) as well as array elements. When issuing the SD-JWT to
the Holder, the Issuer includes the cleartext counterparts of all hidden
claims, the so-called Disclosures, outside the signed part of the SD-JWT.

The Holder decides which claims to disclose to a particular Verifier and includes the respective
Disclosures in the SD-JWT to that Verifier. The Verifier
has to verify that all disclosed claim values were part of the original
Issuer-signed JWT. The Verifier will not, however, learn any claim
values not disclosed in the Disclosures.

This document also specifies an optional mechanism for Key Binding,
which is the concept of binding an SD-JWT to a Holder's public key
and requiring that the Holder prove possession of the corresponding
private key when presenting the SD-JWT.
The strength of the binding is conditional upon the trust
in the protection of the private key of the key pair an SD-JWT is bound to.

SD-JWT can be used with any JSON-based representation of claims, including JSON-LD.

This specification aims to be easy to implement and to leverage
established and widely used data formats and cryptographic algorithms
wherever possible.

## Feature Summary

* This specification defines
 - a format for the payload of an Issuer-signed JWT containing selectively disclosable claims that include object properties (key-value pairs), array elements, and nested data structures built from these,
 - a format for data associated with the JWT that enables selectively disclosing those claims,
 - facilities for binding the JWT to a key and associated data to prove possession thereof, and
 - a format, extending the JWS Compact Serialization, for the combined transport of the JWT and associated data that is suitable for both issuance and presentation.
* An alternate format utilizing the JWS JSON Serialization is also specified.
* This specification enables combining selectively disclosable claims with
  clear-text claims that are always disclosed.
* For selectively disclosable claims that are object properties, both the key and value are always blinded.


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
:  A composite structure, consisting of an Issuer-signed JWT (JWS, [@!RFC7515]), Disclosures, and optionally a Key Binding JWT
 that supports selective disclosure as defined in this document. It can contain both regular claims and digests of selectively-disclosable claims.

Disclosure:
:  A combination of a salt, a cleartext claim name (present when the claim is a key-value pair and absent when the claim is an array element), and a cleartext claim value, all of which are used to calculate a digest for the respective claim.

Key Binding:
:  Ability of the Holder to prove legitimate possession of an SD-JWT by proving
  control over the same private key during the issuance and presentation. An SD-JWT with Key Binding contains
  a public key, or a reference to a public key, that matches to the private key controlled by the Holder.

Key Binding JWT:
:  A JWT for proving Key Binding as defined in (#kb-jwt).

Issuer:
:  An entity that creates SD-JWTs.

Holder:
:  An entity that received SD-JWTs from the Issuer and has control over them.

Verifier:
:  An entity that requests, checks, and extracts the claims from an SD-JWT with its respective Disclosures.

# Flow Diagram

~~~ ascii-art
           +------------+
           |            |
           |   Issuer   |
           |            |
           +------------+
                 |
            Issues SD-JWT
      including all Disclosures
                 |
                 v
           +------------+
           |            |
           |   Holder   |
           |            |
           +------------+
                 |
           Presents SD-JWT
    including selected Disclosures
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

This section describes SD-JWTs with their respective Disclosures and Key Binding at a
conceptual level, abstracting from the data formats described in (#data_formats).

## SD-JWT and Disclosures

An SD-JWT, at its core, is a digitally signed JSON document containing digests over the selectively disclosable claims with the Disclosures outside the document. Disclosures can be omitted without breaking the signature, and modifying them can be detected. Selectively disclosable claims can be individual object properties (key-value pairs) or array elements.

Each digest value ensures the integrity of, and maps to, the respective Disclosure.  Digest values are calculated using a hash function over the Disclosures, each of which contains a cryptographically secure random salt, the claim name (only when the claim is an object property), and the claim value. The Disclosures are sent to the Holder as part of the SD-JWT in the format defined in (#sd-jwt-structure).

An SD-JWT MAY also contain clear-text claims that are always disclosed to the Verifier.

## Disclosing to a Verifier

To disclose to a Verifier a subset of the SD-JWT claim values, a Holder sends only the Disclosures of those selectively released claims to the Verifier as part of the SD-JWT.

## Optional Key Binding

Key Binding is an optional feature. When Key Binding is required by the use-case, the SD-JWT MUST contain information about the key material controlled by the Holder.

Note: How the public key is included in SD-JWT is out of scope of this document. It can be passed by value or by reference.

The Holder can then create a signed document, the Key Binding JWT as defined in (#kb-jwt), using its private key. This document contains some
data provided by the Verifier such as a nonce to ensure the freshness of the signature, and audience to indicate the
intended audience for the document.

The Key Binding JWT can be included as part of the SD-JWT and sent to the Verifier as described in (#sd-jwt-structure).

Note that there may be other ways to send a Key Binding JWT to the Verifier or for the Holder to prove possession of the key material included in an SD-JWT. In these cases, inclusion of the Key Binding JWT in the SD-JWT is not required.

## Verification

At a high level, the Verifier

 * receives the SD-JWT from the Holder and verifies its signature using the Issuer's public key,
 * verifies the Key Binding JWT, if Key Binding is required by the Verifier's policy, using the public key included in the SD-JWT,
 * calculates the digests over the Holder-Selected Disclosures and verifies that each digest is contained in the SD-JWT.

The detailed algorithm is described in (#verifier_verification).

# Data Formats {#data_formats}

This section defines data formats for SD-JWT including the Issuer-signed JWT content, Disclosures, and Key Binding JWT.

## SD-JWT Payload

An SD-JWT has a JWT component that MUST be signed using the Issuer's private key.
It MUST use a JWS asymmetric digital signature algorithm. It
MUST NOT use `none` or an identifier for a symmetric algorithm (MAC).

The payload of an SD-JWT is a JSON object according to the following rules:

 1. The payload MAY contain the `_sd_alg` key described in (#hash_function_claim).
 2. The payload MAY contain one or more digests of Disclosures to enable selective disclosure of the respective claims, created and formatted as described below.
 3. The payload MAY contain one or more decoy digests to obscure the actual number of claims in the SD-JWT, created and formatted as described in (#decoy_digests).
 4. The payload MAY contain one or more non-selectively disclosable claims.
 5. The payload MAY also contain Holder's public key(s) or reference(s) thereto, as well as further claims such as `iss`, `iat`, etc. as defined or required by the application using SD-JWTs.
 6. The payload MUST NOT contain the reserved claims `_sd` or `...` except for the purpose of transporting digests as described below.
 7. The same digest value MUST NOT appear more than once in the SD-JWT.

Applications of SD-JWT SHOULD be explicitly typed using the `typ` header parameter. See (#explicit_typing) for more details.

It is the Issuer who decides which claims are selectively disclosable and which are not. End-User claims MAY be included as plaintext as well, e.g., if hiding the particular claims from the Verifier is not required in the intended use case. See (#sd-validity-claims) for considerations on making validity-controlling claims such as `exp` selectively disclosable.

Claims that are not selectively disclosable are included in the SD-JWT in plaintext just as they would be in any other JSON structure.


## Creating Disclosures {#creating_disclosures}

Disclosures are created differently depending on whether a claim is an object property (key-value pair) or an array element.

 * For a claim that is an object property, the Issuer creates a Disclosure as described in (#disclosures_for_object_properties).
 * For a claim that is an array element, the Issuer creates a Disclosure as described in (#disclosures_for_array_elements).

### Disclosures for Object Properties {#disclosures_for_object_properties}
For each claim that is an object property and that is to be made selectively disclosable, the Issuer MUST create a Disclosure as follows:

 * Create an array of three elements in this order:
   1. A salt value. MUST be a string. See (#salt-entropy) and (#salt_minlength) for security considerations. It is RECOMMENDED to base64url-encode minimum 128 bits of cryptographically secure random data, producing a string. The salt value MUST be unique for each claim that is to be selectively disclosed. The Issuer MUST NOT disclose the salt value to any party other than the Holder.
   2. The claim name, or key, as it would be used in a regular JWT payload. The value MUST be a string.
   3. The claim value, as it would be used in a regular JWT payload. The value MAY be of any type that is allowed in JSON, including numbers, strings, booleans, arrays, and objects.
 * JSON-encode the array, producing an UTF-8 string.
 * base64url-encode the byte representation of the UTF-8 string, producing a US-ASCII [@RFC0020] string. This string is the Disclosure.

The order is decided based on the readability considerations: salts would have a
constant length within the SD-JWT, claim names would be around the same length
all the time, and claim values would vary in size, potentially being large
objects.

The following example illustrates the steps described above.

The array is created as follows:
```json
["_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius"]
```

The resulting Disclosure would be: `WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0`

Note that variations in whitespace, encoding of Unicode characters, ordering of object properties, etc., are allowed
in the JSON representation and no canonicalization needs be performed before base64url-encoding.
For example, the following strings are all valid and encode the
same claim value "Möbius":

 * A different way to encode the unicode umlaut:\
`WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNX`\
`HUwMGY2Yml1cyJd`
 * No white space:\
`WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Y`\
`ml1cyJd`
 * Newline characters between elements:\
`WwoiXzI2YmM0TFQtYWM2cTJLSTZjQlc1ZXMiLAoiZmFtaWx5X25hbWUiLAoiT`\
`cO2Yml1cyIKXQ`

See (#disclosure_format_considerations) for some further considerations on the Disclosure format approach.

### Disclosures for Array Elements {#disclosures_for_array_elements}

For each claim that is an array element and that is to be made selectively disclosable, the Issuer MUST create a Disclosure as follows:

 * The array MUST contain two elements in this order:
   1. The salt value as described in (#disclosures_for_object_properties).
   2. The array element that is to be hidden. This value MAY be of any type that is allowed in JSON, including numbers, strings, booleans, arrays, and objects.

The Disclosure string is created by JSON-encoding this array and base64url-encoding the byte representation of the resulting string as described in (#disclosures_for_object_properties). The same considerations regarding
variations in the result of the JSON encoding apply.

For example, a Disclosure for the second element of the `nationalities` array in the following claim set:

```json
{
  "nationalities": ["DE", "FR"]
}
```

could be created by first creating the following array:

```json
["lklxF5jMYlGTPUovMNIvCA", "FR"]
```

The resulting Disclosure would be: `WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0`

## Hashing Disclosures {#hashing_disclosures}

For embedding the Disclosures in the SD-JWT, the Disclosures are hashed using the hash algorithm specified in the `_sd_alg` claim described in (#hash_function_claim). The resulting digest is then included in the SD-JWT payload instead of the original claim value, as described next.

The digest MUST be taken over the US-ASCII bytes of the base64url-encoded Disclosure. This follows the convention in JWS [@!RFC7515] and JWE [@RFC7516]. The bytes of the digest MUST then be base64url-encoded.

It is important to note that:

 * The input to the hash function MUST be the base64url-encoded Disclosure, not the bytes encoded by the base64url string.
 * The bytes of the output of the hash function MUST be base64url-encoded, and are not the bytes making up the (often used) hex representation of the bytes of the digest.

For example, the SHA-256 digest of the Disclosure
`WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0` would be
`uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY`.

The SHA-256 digest of the Disclosure
`WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0` would be
`w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs`.

## Embedding Disclosure Digests in SD-JWTs {#embedding_disclosure_digests}

For selectively disclosable claims, the digests of the Disclosures are embedded into the SD-JWT instead of the claims themselves. The precise way of embedding depends on whether a claim is an object property (key-value pair) or an array element.

 * For a claim that is an object property, the Issuer embeds a Disclosure as described in (#embedding_object_properties).
* For a claim that is an array element, the Issuer creates a Disclosure as described in (#embedding_array_elements).

### Object Properties {#embedding_object_properties}

Digests of Disclosures for object properties are added to an array under the new
key `_sd` in the object. The `_sd` key MUST refer to an array of strings, each
string being a digest of a Disclosure or a decoy digest as described in (#decoy_digests).

The array MAY be empty in case the Issuer decided not to selectively disclose
any of the claims at that level. However, it is RECOMMENDED to omit the `_sd`
key in this case to save space.

The Issuer MUST hide the original order of the claims in the array. To ensure
this, it is RECOMMENDED to shuffle the array of hashes, e.g., by sorting it
alphanumerically or randomly, after potentially adding
decoy digests as described in (#decoy_digests). The precise method does not matter as long as it
does not depend on the original order of elements.

For example, using the digest of the object property Disclosure created above,
the Issuer could create the following SD-JWT payload to make `family_name`
selectively disclosable:

```json
{
  "given_name": "Alice",
  "_sd": ["uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY"]
}
```

### Array Elements {#embedding_array_elements}

Digests of Disclosures for array elements are added to the array in the same
position as the original claim value in the array. For each digest, an object
of the form `{"...": "<digest>"}` is added to the array. The key MUST always be the
string `...` (three dots). The value MUST be the digest of the Disclosure created as
described in (#hashing_disclosures). There MUST NOT be any other keys in the
object.

For example, using the digest of the array element Disclosure created above,
the Issuer could create the following SD-JWT payload to make the second element
of the `nationalities` array selectively disclosable:

```json
{
  "nationalities":
    ["DE", {"...": "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"}]
}
```

As described in (#verifier_verification), Verifiers ignore all selectively
disclosable array elements for which they did not receive a Disclosure. In the
example above, the verification process would output an array with only one
element unless a matching Disclosure for the second element is received.

## Example 1: SD-JWT {#example-1}

In this example, a simple SD-JWT is demonstrated.

The Issuer is using the following input claim set:

<{{examples/simple/user_claims.json}}

The Issuer in this case made the following decisions:

* The `nationalities` array is always visible, but its contents are selectively disclosable.
* The `sub` element and essential verification data (`iss`, `iat`, `cnf`, etc.) are always visible.
* All other End-User claims are selectively disclosable.
* For `address`, the Issuer is using a flat structure, i.e., all of the claims
  in the `address` claim can only be disclosed in full. Other options are
  discussed in (#nested_data).

The following payload is used for the SD-JWT:

<{{examples/simple/sd_jwt_payload.json}}

The following Disclosures are created by the Issuer:

{{examples/simple/disclosures.md}}

The payload is then signed by the Issuer to create a JWT like the following:

<{{examples/simple/sd_jwt_jws_part.txt}}

## Decoy Digests {#decoy_digests}

An Issuer MAY add additional digests to the SD-JWT payload that are not associated with
any claim.  The purpose of such "decoy" digests is to make it more difficult for
an attacker to see the original number of claims contained in the SD-JWT. Decoy
digests MAY be added both to the `_sd` array for objects as well as in arrays.

It is RECOMMENDED to create the decoy digests by hashing over a
cryptographically secure random number. The bytes of the digest MUST then be
base64url-encoded as above. The same digest function as for the Disclosures MUST
be used.

For decoy digests, no Disclosure is sent to the Holder, i.e., the Holder will
see digests that do not correspond to any Disclosure. See
(#decoy_digests_privacy) for additional privacy considerations.

To ensure readability and replicability, the examples in this specification do
not contain decoy digests unless explicitly stated. For an example
with decoy digests, see (#example-simple_structured).

## Nested Data in SD-JWTs {#nested_data}

Being JSON, an object in an SD-JWT payload MAY contain key-value pairs where the value is another object or objects MAY be elements in arrays. In SD-JWT, the Issuer decides for each claim individually, on each level of the JSON, whether the claim should be selectively disclosable or not. This choice can be made on each level independent from whether keys higher in the hierarchy are selectively disclosable.

From this it follows that the `_sd` key containing digests MAY appear multiple
times in an SD-JWT, and likewise, there MAY be multiple arrays within the
hierarchy with each having selectively disclosable elements. Digests of
selectively disclosable claims MAY even appear within other Disclosures.

The following examples illustrate some of the options an Issuer has. It is up to the Issuer to decide which option to use, depending on, for example, the expected use cases for the SD-JWT, requirements for privacy, size considerations, or ecosystem requirements. For more examples with nested structures, see (#example-simple_structured) and (#example-complex-structured-sd-jwt).

The following input claim set is used as an example throughout this section:

<{{examples/address_only_flat/user_claims.json}}

Important: Throughout the examples in this document, line breaks had to
be added to JSON strings and base64-encoded strings (as shown in the
next example) to adhere to the 72 character limit for lines in RFCs and
for readability. JSON does not allow line breaks in strings.

### Option 1: Flat SD-JWT

The Issuer can decide to treat the `address` claim as a block that can either be disclosed completely or not at all. The following example shows that in this case, the entire `address` claim is treated as an object in the Disclosure.

<{{examples/address_only_flat/sd_jwt_payload.json}}

The Issuer would create the following Disclosure:

{{examples/address_only_flat/disclosures.md}}

### Option 2: Structured SD-JWT

The Issuer may instead decide to make the `address` claim contents selectively disclosable individually:

<{{examples/address_only_structured/sd_jwt_payload.json}}

In this case, the Issuer would use the following data in the Disclosures for the `address` sub-claims:

{{examples/address_only_structured/disclosures.md}}

The Issuer may also make one sub-claim of `address` non-selectively disclosable and hide only the other sub-claims:

<{{examples/address_only_structured_one_open/sd_jwt_payload.json}}

There would be no Disclosure for `country` in this case.

### Option 3: SD-JWT with Recursive Disclosures

The Issuer may also decide to make the `address` claim contents selectively disclosable recursively, i.e., the `address` claim is made selectively disclosable as well as its sub-claims:

<{{examples/address_only_recursive/sd_jwt_payload.json}}

The Issuer creates Disclosures first for the sub-claims and then includes their digests in the Disclosure for the `address` claim:

{{examples/address_only_recursive/disclosures.md}}

## Hash Function Claim {#hash_function_claim}

The claim `_sd_alg` indicates the hash algorithm used by the Issuer to generate
the digests as described in (#creating_disclosures). When used, this claim MUST
appear at the top level of the SD-JWT payload. It
MUST NOT be used in any object nested within the payload. If the  `_sd_alg`
claim is not present at the top level, a default value of `sha-256` MUST be used.

The hash algorithm identifier MUST be a hash algorithm value from the "Hash Name
String" column in the IANA "Named Information Hash Algorithm" registry
[@IANA.Hash.Algorithms] or a value defined in another specification and/or
profile of this specification.

To promote interoperability, implementations MUST support the `sha-256` hash
algorithm.

See (#security_considerations) for requirements regarding entropy of the salt,
minimum length of the salt, and choice of a hash algorithm.

## Holder Public Key Claim {#holder_public_key_claim}

If the Issuer wants to enable Key Binding, it includes a public key
associated with the Holder, or a reference thereto.

It is out of the scope of this document to describe how the Holder key pair is
established. For example, the Holder MAY create a key pair and provide a public key to the Issuer,
the Issuer MAY create the key pair for the Holder, or
Holder and Issuer MAY use pre-established key material.

Note: The examples in this document use the `cnf` claim defined in [@RFC7800] to include
the raw public key by value in SD-JWT.

## Key Binding JWT {#kb-jwt}

This section defines the contents of the Key Binding JWT, which
the Holder MAY include in the SD-JWT to prove the Key Binding to the Verifier.

The JWT MUST contain the following elements:

* in the JOSE header,
    * `typ`: REQUIRED. MUST be `kb+jwt`, which explicitly types the Key Binding JWT as recommended in Section 3.11 of [@!RFC8725].
    * `alg`: REQUIRED. A digital signature algorithm identifier such as per IANA "JSON Web Signature and Encryption Algorithms" registry. MUST NOT be `none` or an identifier for a symmetric algorithm (MAC).
* in the JWT payload,
    * `iat`: REQUIRED. The value of this claim MUST be the time at which the Key Binding JWT was issued using the syntax defined in [@!RFC7519].
    * `aud`: REQUIRED. The intended receiver of the Key Binding JWT. How the value is represented is up to the protocol used and out of scope of this specification.
    * `nonce`: REQUIRED. Ensures the freshness of the signature. The value type of this claim MUST be a string. How this value is obtained is up to the protocol used and out of scope of this specification.

To validate the signature on the Key Binding JWT, the Verifier MUST use the key material in the SD-JWT. If it is not clear from the SD-JWT, the Key Binding JWT MUST specify which key material the Verifier needs to use to validate the Key Binding JWT signature using JOSE header parameters such as `kid` and `x5c`.

Below is a non-normative example of a Key Binding JWT header:

```
{
  "alg": "ES256",
  "typ": "kb+jwt"
}
```

Below is a non-normative example of a Key Binding JWT payload:

<{{examples/simple/kb_jwt_payload.json}}

Below is a non-normative example of a Key Binding JWT produced by signing a payload in the example above:

<{{examples/simple/kb_jwt_serialized.txt}}

Whether to require Key Binding is up to the Verifier's policy,
based on the set of trust requirements such as trust frameworks it belongs to.

Other ways of proving Key Binding MAY be used when supported by the Verifier,
e.g., when the presented SD-JWT without a Key Binding JWT is itself embedded in a
signed JWT. See (#enveloping) for details.

## SD-JWT Structure {#sd-jwt-structure}

An SD-JWT is composed of the following:

* the Issuer-signed JWT
* zero or more Disclosures
* optionally a Key Binding JWT

The serialized format for the SD-JWT is the concatenation of each part delineated with a single tilde ('~') character as follows:

```
<JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~<optional KB-JWT>
```

The order of the tilde separated values MUST be the Issuer-signed JWT, followed by any Disclosures, and lastly the optional Key Binding JWT.
In the case that there is no Key Binding JWT, the last element MUST be an empty string and the last separating tilde character MUST NOT be omitted.

The Disclosures are linked to the SD-JWT payload through the
digest values included therein.

When issued to a Holder, the Issuer includes all the relevant Disclosures in the SD-JWT.

For presentation to a Verifier, the Holder sends the SD-JWT including only its selected
set of the Disclosures to the Verifier.

The Holder MAY send any subset of the Disclosures to the Verifier, i.e.,
none, multiple, or all Disclosures. For data that the Holder does not want to reveal
to the Verifier, the Holder MUST NOT send Disclosures or reveal the salt values in any
other way.

A Holder MUST NOT send a Disclosure that was not included in the SD-JWT or send
a Disclosure more than once.

For [Example 1](#example-1), a non-normative example of an issued SD-JWT might look as follows (with Line breaks for formatting only):

<{{examples/simple/sd_jwt_issuance.txt}}

The following non-normative example shows an associated SD-JWT Presentation as it would be sent from the Holder to the Verifier.
The claims `given_name`, `family_name`, and `address` are disclosed and the Key Binding JWT is included as the last element.

<{{examples/simple/sd_jwt_presentation.txt}}

# Verification and Processing {#verification}

## Verification of the SD-JWT {#sd_jwt_verification}

Upon receiving an SD-JWT, a Holder or a Verifier MUST ensure that

 * the Issuer-signed JWT is valid, i.e., it is signed by the Issuer and the signature is valid, and
 * all Disclosures are correct, i.e., their digests are referenced in the Issuer-signed JWT.

The Holder or the Verifier MUST perform the following (or equivalent) steps when receiving
an SD-JWT:

 1. Separate the SD-JWT into the Issuer-signed JWT, the Disclosures (if any), and the Key Binding JWT (if present).
 2. Validate the Issuer-signed JWT:
    1. Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [@RFC8725], Sections 3.1 and 3.2 for details. The `none` algorithm MUST NOT be accepted.
    2. Validate the signature over the Issuer-signed JWT.
    3. Validate the Issuer and that the signing key belongs to this Issuer.
    5. Check that the `_sd_alg` claim value is understood and the hash algorithm is deemed secure.
 3. Process the Disclosures and embedded digests in the Issuer-signed JWT as follows:
    1. For each Disclosure provided:
       1. Calculate the digest over the base64url-encoded string as described in (#hashing_disclosures).
    2. (*) Identify all embedded digests in the Issuer-signed JWT as follows:
       1. Find all objects having an `_sd` key that refers to an array of strings.
       2. Find all array elements that are objects with one key, that key being `...` and referring to a string.
    3. (**) For each embedded digest found in the previous step:
       1. Compare the value with the digests calculated previously and find the matching Disclosure. If no such Disclosure can be found, the digest MUST be ignored.
       2. If the digest was found in an object's `_sd` key:
          1. If the respective Disclosure is not a JSON-encoded array of three elements, the SD-JWT MUST be rejected.
          2. Insert, at the level of the `_sd` key, a new claim using the claim name and claim value from the Disclosure.
          3. If the claim name already exists at the same level, the SD-JWT MUST be rejected.
          4. Recursively process the value using the steps described in (*) and (**).
       3. If the digest was found in an array element:
          1. If the respective Disclosure is not a JSON-encoded array of two elements, the SD-JWT MUST be rejected.
          2. Replace the array element with the claim value from the Disclosure.
          3. Recursively process the value using the steps described in (*) and (**).
    4. If any digests were found more than once in the previous step, the SD-JWT MUST be rejected.
    5. Remove all array elements for which the digest was not found in the previous step.
    6. Remove all `_sd` keys and their contents from the Issuer-signed JWT payload.
    7. Remove the claim `_sd_alg` from the SD-JWT payload.
 4. Check that the SD-JWT is valid using claims such as `nbf`, `iat`, and `exp` in the processed payload. If a required validity-controlling claim is missing (see (#sd-validity-claims)), the SD-JWT MUST be rejected.

If any step fails, the SD-JWT is not valid and processing MUST be aborted.

It is up to the Holder how to maintain the mapping between the Disclosures and the plaintext claim values to be able to display them to the End-User when needed.

## Processing by the Holder  {#holder_verification}

If a Key Binding JWT is received by a Holder, the SD-JWT SHOULD be rejected.

For presentation to a Verifier, the Holder MUST perform the following (or equivalent) steps:

 1. Decide which Disclosures to release to the Verifier, obtaining proper End-User consent if necessary.
 2. If Key Binding is required, create a Key Binding JWT.
 3. Assemble the SD-JWT for Presentation, including the Issuer-signed JWT, the selected Disclosures and, if applicable, the Key Binding JWT.
 4. Send the Presentation to the Verifier.

## Verification by the Verifier  {#verifier_verification}

Upon receiving a Presentation, in addition to the checks outlined in (#sd_jwt_verification), Verifiers MUST ensure that

 * if Key Binding is required, the Key Binding JWT is signed by the Holder and valid.

To this end, Verifiers MUST follow the following steps (or equivalent):

 1. Determine if Key Binding is to be checked according to the Verifier's policy
    for the use case at hand. This decision MUST NOT be based on whether
    a Key Binding JWT is provided by the Holder or not. Refer to (#key_binding_security) for
    details.
 2. Process the SD-JWT as defined in (#sd_jwt_verification).
 3. If Key Binding is required:
    1. If Key Binding is provided by means not defined in this specification, verify the Key Binding according to the method used.
    2. Otherwise, verify the Key Binding JWT as follows:
       1. If a Key Binding JWT is not provided, the Verifier MUST reject the Presentation.
       2. Determine the public key for the Holder from the SD-JWT.
       3. Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [@RFC8725], Sections 3.1 and 3.2 for details. The `none` algorithm MUST NOT be accepted.
       4. Validate the signature over the Key Binding JWT.
       5. Check that the `typ` of the Key Binding JWT is `kb+jwt`.
       6. Check that the creation time of the Key Binding JWT, as determined by the `iat` claim, is within an acceptable window.
       7. Determine that the Key Binding JWT is bound to the current transaction and was created for this Verifier (replay protection) by validating `nonce` and `aud` claims.
       8. Check that the Key Binding JWT is valid in all other respects, per [@!RFC7519] and [@!RFC8725].

If any step fails, the Presentation is not valid and processing MUST be aborted.

Otherwise, the processed SD-JWT payload can be passed to the application to be used for the intended purpose.

# Enveloping SD-JWTs {#enveloping}

In some applications or transport protocols, it is desirable to put an SD-JWT into an outer JWT container. For example, an implementation may envelope multiple credentials and presentations, independent of their format, in a JWT to enable application-layer encryption during transport.

For such use cases, the SD-JWT SHOULD be transported as a single string. Key Binding MAY be achieved by signing the envelope JWT instead of including a separate Key Binding JWT in the SD-JWT.

The following non-normative example shows an SD-JWT Presentation enveloped in a JWT:

```
{
  "aud": "https://verifier.example.org",
  "iat": 1580000000,
  "nonce": "iRnRdKuu1AtLM4ltc16by2XF0accSeutUescRw6BWC14",
  "_sd_jwt": "eyJhbGci...emhlaUJhZzBZ~eyJhb...dYALCGg~"
}
```

Here, the SD-JWT is shown as the value of an `_sd_jwt` claim where `eyJhbGci...emhlaUJhZzBZ` represents the Issuer-signed JWT and `eyJhb...dYALCGg` represents a Disclosure. The SD-JWT does not contain a Key Binding JWT as the outer container can be signed instead.

Other specifications or profiles of this specification may define alternative formats for transporting an SD-JWT that envelope multiple such objects into one object and provide Key Binding using means other than the Key Binding JWT.

# JWS JSON Serialization {#json_serialization}

This section describes an optional alternate format for SD-JWT using the JWS JSON Serialization from [@!RFC7515].

For both the General and Flattened JSON Serialization, the SD-JWT is represented as a JSON object according
to Section 7.2 of [@!RFC7515]. The disclosures (both for issuance and presentation) are included in the
serialized JWS using the key `disclosures` at the top-level of the JSON object (the same level as the `payload` member). The
value of the `disclosures` member is an array of strings where each element is an individual Disclosure
as described in (#creating_disclosures). The Issuer includes a Disclosure for each selectively
disclosable claim of the SD-JWT payload, whereas the Holder includes only the Disclosures
selected for the given presentation. Additionally, for presentation with a Key Binding, the Holder adds
the key `kb_jwt` at the top-level of the serialized JWS with a string value containing the
Key Binding JWT as described in (#kb-jwt).

Verification of the JWS JSON serialized SD-JWT follows the same rules defined in (#verification),
except that the SD-JWT does not need to be split into component parts, but disclosures and (if applicable)
a Key Binding JWT can be found in the respective members of the JSON object.

Using a payload similar to that from [Example 1](#example-1), the following is a non-normative example of
a JWS JSON serialized SD-JWT from an Issuer with all the respective Disclosures.

<{{examples/json_serialization/sd_jwt_issuance.json}}

Below is a non-normative example of a presentation of the JWS JSON serialized SD-JWT, where the Holder
includes a Key Binding JWT and has selected to disclose `given_name`, `family_name`, and `address`.

<{{examples/json_serialization/sd_jwt_presentation.json}}



# Security Considerations {#security_considerations}

Security considerations in this section help achieve the following properties:

**Selective Disclosure:** An adversary in the role of the Verifier cannot obtain
information from an SD-JWT about any claim name or claim value that was not
explicitly disclosed by the Holder unless that information can be derived from
other disclosed claims or sources other than the presented SD-JWT.

**Integrity:** A malicious Holder cannot modify names or values of selectively disclosable claims without detection by the Verifier.

Additionally, as described in (#key_binding_security), the application of Key Binding can ensure that the presenter of an SD-JWT credential is the legitimate Holder of the credential.

## Mandatory Signing of the Issuer-signed JWT {#sec-is-jwt}

The Issuer-signed JWT MUST be signed by the Issuer to protect integrity of the issued
claims. An attacker can modify or add claims if this JWT is not signed (e.g.,
change the "email" attribute to take over the victim's account or add an
attribute indicating a fake academic qualification).

The Verifier MUST always check the signature of the Issuer-signed JWT to ensure that it
has not been tampered with since the issuance. The Issuer-signed JWT MUST be rejected if the signature cannot be verified.

The security of the Issuer-signed JWT depends on the security of the signature algorithm.
Any of the JWS asymmetric digital signature algorithms registered in [@IANA.JWS.Algorithms]
can be used, including post-quantum algorithms, when they are ready.

## Manipulation of Disclosures {#sec-disclosures}

Holders can manipulate the Disclosures by changing the values of the claims
before sending them to the Verifier. The Verifier MUST check the Disclosures to
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

Furthermore, the hash algorithms MD2, MD4, MD5, and SHA-1
revealed fundamental weaknesses and they MUST NOT be used.

## Key Binding {#key_binding_security}
Key Binding aims to ensure that the presenter of an SD-JWT credential is actually the legitimate Holder of the credential.
An SD-JWT with Key Binding contains a public key, or a reference to a public key, that corresponds to a private key possessed by the Holder.
The Verifier requires that the Holder prove possession of that private key when presenting the SD-JWT credential.

Without Key Binding, a Verifier only gets the proof that the
credential was issued by a particular Issuer, but the credential itself
can be replayed by anyone who gets access to it. This means that, for
example, after a credential was leaked to an attacker, the attacker can
present the credential to any verifier that does not require a
binding. But also a malicious Verifier to which the Holder presented the
credential can present the credential to another Verifier if that other
Verifier does not require Key Binding.

Verifiers MUST decide whether Key Binding is required for a
particular use case before verifying a credential. This decision
can be informed by various factors including, but not limited to the following:
business requirements, the use case, the type of
binding between a Holder and its credential that is required for a use
case, the sensitivity of the use case, the expected properties of a
credential, the type and contents of other credentials expected to be
presented at the same time, etc.

It is important that a Verifier does not make its security policy
decisions based on data that can be influenced by an attacker or that
can be misinterpreted. For this reason, when deciding whether Key
Binding is required or not, Verifiers MUST NOT take into account

 * whether a Key Binding JWT is present or not, as an attacker can
   remove the Key Binding JWT from any Presentation and present it to the
   Verifier, or
 * whether Key Binding data is present in the SD-JWT or not, as the
   Issuer might have added the key to the SD-JWT in a format/claim that
   is not recognized by the Verifier.

If a Verifier has decided that Key Binding is required for a
particular use case and the Key Binding is not present, does not fulfill the requirements
(e.g., on the signing algorithm), or no recognized
Key Binding data is present in the SD-JWT, the Verifier will reject the
presentation, as described in (#verifier_verification).

### Key Binding JWT

Issuer provided integrity protection of the SD-JWT payload and Disclosures is achieved by the signature on the Issuer-signed JWT that covers the SD-JWT payload including the digest values of the Disclosures as described in (#sec-is-jwt) and (#sec-disclosures), respectively. The Key Binding JWT, defined in (#kb-jwt), serves exclusively as a mechanism for the Holder to demonstrate possession of the private key corresponding to the public key in the SD-JWT payload. As such, the signature on the Key Binding JWT does not cover other parts of the SD-JWT. In cases where it's desirable for the Holder's signature to convey more than a proof-of-possession, such as signing over the selected Disclosures to prove those were the Disclosures selected, the SD-JWT to be presented can be embedded in another JWT (as described in [Enveloping SD-JWTs](#enveloping)) or otherwise signed by the Holder via the application protocol delivering it.

## Blinding Claim Names {#blinding-claim-names}

SD-JWT ensures that names of claims that are selectively disclosable are
always blinded. This prevents an attacker from learning the names of the
disclosable claims. However, the names of the claims that are not
disclosable are not blinded. This includes the keys of objects that themselves
are not blinded, but contain disclosable claims. This limitation
needs to be taken into account by Issuers when creating the structure of
the SD-JWT.

## Selectively-Disclosable Validity Claims {#sd-validity-claims}

Claims controlling the validity of the SD-JWT, such as `nbf`, `iat`, and `exp`,
are usually included in plaintext in the SD-JWT payload, but MAY be
selectively disclosable instead. In this case, however, it is up to the Holder
to release the claims to the Verifier. A malicious Holder may try to hide, for
example, an expiration time (`exp`) in order to get a Verifier that "fails open"
to accept an expired SD-JWT.

Verifiers therefore MUST ensure that all claims they deem necessary for checking
the validity of the SD-JWT are present (or disclosed, respectively) before
checking the validity and accepting the SD-JWT. This is implemented in the last
step of the verification defined in (#sd_jwt_verification).

The precise set of required validity claims will typically be defined by
ecosystem rules or the credential format and MAY include claims other than
`nbf`, `iat`, and `exp`.

## Issuer Signature Key Distribution and Rotation {#issuer_signature_key_distribution}

This specification does not define how signature verification keys of
Issuers are distributed to Verifiers. However, it is RECOMMENDED that
Issuers publish their keys in a way that allows for efficient and secure
key rotation and revocation, for example, by publishing keys at a
predefined location using the JSON Web Key Set (JWKS) format [@RFC7517].
Verifiers need to ensure that they are not using expired or revoked keys
for signature verification using reasonable and appropriate means for the given
key-distribution method.

## Forwarding Credentials

When Key Binding is not enforced,
any entity in possession of an SD-JWT Presentation can forward the contents to third parties.
When doing so, that entity may remove Disclosures such that the receiver
learns only a subset of the claims contained in the original SD-JWT.

For example, a device manufacturer might produce an SD-JWT
containing information about upstream and downstream supply chain contributors.
Each supply chain party can verify only the claims that were selectively disclosed to them
by an upstream party, and they can choose to further reduce the disclosed claims
when presenting to a downstream party.

In some scenarios this behavior could be desirable,
but if it is not, Issuers need to support and Verifiers need to enforce Key Binding.

## Explicit Typing {#explicit_typing}

Section 3.11 of [@RFC8725] describes the use of explicit typing to prevent confusion attacks
in which one kind of JWT is mistaken for another. SD-JWTs are also potentially
vulnerable to such confusion attacks, so it is RECOMMENDED to specify an explicit type
by including the `typ` header parameter when the SD-JWT is issued, and for Verifiers to check this value.

When explicit typing is employed for an SD-JWT, it is RECOMMENDED that a media type name of the format
"application/example+sd-jwt" be used, where "example" is replaced by the identifier for the specific kind of SD-JWT.
The definition of `typ` in Section 4.1.9 of [@!RFC7515] recommends that the "application/" prefix be omitted, so
"example+sd-jwt" would be the value of the `typ` header parameter.

# Privacy Considerations {#privacy_considerations}

The privacy principles of [@ISO.29100] should be adhered to.

## Storage of Signed User Data

Wherever End-User data is stored, it represents a potential
target for an attacker. This target can be of particularly
high value when the data is signed by a trusted authority like an
official national identity service. For example, in OpenID Connect,
signed ID Tokens can be stored by Relying Parties. In the case of
SD-JWT, Holders have to store SD-JWTs,
and Issuers and Verifiers may decide to do so as well.

Not surprisingly, a leak of such data risks revealing private data of End-Users
to third parties. Signed End-User data, the authenticity of which
can be easily verified by third parties, further exacerbates the risk.
As discussed in (#key_binding_security), leaked
SD-JWTs may also allow attackers to impersonate Holders unless Key
Binding is enforced and the attacker does not have access to the
Holder's cryptographic keys. Altogether, leaked SD-JWT credentials may have
a high monetary value on black markets.

Due to these risks, systems implementing SD-JWT SHOULD be designed to
minimize the amount of data that is stored. All involved parties SHOULD
store SD-JWTs only for as long as needed, including in log files.

Issuers SHOULD NOT store SD-JWTs after issuance.

Holders SHOULD store SD-JWTs only in
encrypted form, and, wherever possible, use hardware-backed encryption
in particular for the private Key Binding key. Decentralized storage
of data, e.g., on End-User devices, SHOULD be preferred for End-User
credentials over centralized storage. Expired SD-JWTs SHOULD be deleted
as soon as possible.

Verifiers SHOULD NOT store SD-JWTs after verification. It may be
sufficient to store the result of the verification and any End-User data
that is needed for the application.

If reliable and secure key rotation and revocation is ensured according
to (#issuer_signature_key_distribution), Issuers may opt to publish
expired or revoked private signing keys (after a grace period that
ensures that the keys are not cached any longer at any Verifier). This
reduces the value of any leaked credentials as the signatures on them
can no longer be trusted to originate from the Issuer.


## Confidentiality during Transport

If the SD-JWT is transmitted over an insecure
channel during issuance or presentation, an adversary may be able to
intercept and read the End-User's personal data or correlate the information with previous uses of the same SD-JWT.

Usually, transport protocols for issuance and presentation of credentials
are designed to protect the confidentiality of the transmitted data, for
example, by requiring the use of TLS.

This specification therefore considers the confidentiality of the data to be
provided by the transport protocol and does not specify any encryption
mechanism.

Implementers MUST ensure that the transport protocol provides confidentiality
if the privacy of End-User data or correlation attacks by passive observers are a concern.

To encrypt the SD-JWT when transmitted over an insecure channel, implementers MAY use JSON Web Encryption (JWE) [@!RFC7516] by nesting the SD-JWT as the plaintext payload of a JWE.
Especially, when an SD-JWT is transmitted via a URL and information may be stored/cached in the browser or end up in web server logs, the SD-JWT SHOULD be encrypted using JWE.

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


## Issuer Identifier

An Issuer issuing only one type of SD-JWT might have privacy implications, because if the Holder has an SD-JWT issued by that Issuer, its type and claim names can be determined.

For example, if the National Cancer Institute only issued SD-JWTs with cancer registry information, it is possible to deduce that the Holder owning its SD-JWT is a cancer patient.

Moreover, the issuer identifier alone may reveal information about the user.

For example, when a military organization or a drug rehabilitation center issues a vaccine credential, verifiers can deduce that the holder is a military member or may have a substance use disorder.

To mitigate this issue, a group of issuers may elect to use a common Issuer identifier. A group signature scheme outside the scope of this specification may also be used, instead of an individual signature.

# Acknowledgements {#Acknowledgements}

We would like to thank
Alen Horvat,
Arjan Geluk,
Christian Bormann,
Christian Paquin,
David Bakker,
David Waite,
Fabian Hauck,
Filip Skokan,
Giuseppe De Marco,
John Mattsson,
Justin Richer,
Kushal Das,
Matthew Miller,
Mike Jones,
Mike Prorock,
Nat Sakimura,
Oliver Terbu,
Orie Steele,
Paul Bastian,
Pieter Kasselman,
Ryosuke Abe,
Shawn Butterfield,
Tobias Looker,
Takahiko Kawasaki,
Torsten Lodderstedt,
Vittorio Bertocci, and
Yaron Sheffer
for their contributions (some of which substantial) to this draft and to the initial set of implementations.

The work on this draft was started at OAuth Security Workshop 2022 in Trondheim, Norway.


# IANA Considerations {#iana_considerations}

TBD

## Media Type Registration

This section requests registration of the "application/sd-jwt" media type [@RFC2046] in
the "Media Types" registry [@IANA.MediaTypes] in the manner described
in [@RFC6838].

To indicate that the content is an SD-JWT:

* Type name: application
* Subtype name: sd-jwt
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: binary; application/sd-jwt values are a series of base64url-encoded values (some of which may be the empty string) separated by period ('.') or tilde ('~') characters.
* Security considerations: See the Security Considerations section of [[ this specification ]], [@!RFC7519], and [@RFC8725].
* Interoperability considerations: n/a
* Published specification: [[ this specification ]]
* Applications that use this media type: TBD
* Fragment identifier considerations: n/a
* Additional information:
   Magic number(s): n/a
   File extension(s): n/a
   Macintosh file type code(s): n/a
* Person & email address to contact for further information: Daniel Fett, mail@danielfett.de
* Intended usage: COMMON
* Restrictions on usage: none
* Author: Daniel Fett, mail@danielfett.de
* Change Controller: IESG
* Provisional registration?  No

To indicate that the content is a Key Binding JWT:

* Type name: application
* Subtype name: kb+jwt
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: binary; A Key Binding JWT is a JWT; JWT values are encoded as a series of base64url-encoded values (some of which may be the empty string) separated by period ('.') characters.
* Security considerations: See the Security Considerations section of [[ this specification ]], [@!RFC7519], and [@RFC8725].
* Interoperability considerations: n/a
* Published specification: [[ this specification ]]
* Applications that use this media type: TBD
* Fragment identifier considerations: n/a
* Additional information:
   Magic number(s): n/a
   File extension(s): n/a
   Macintosh file type code(s): n/a
* Person & email address to contact for further information: Daniel Fett, mail@danielfett.de
* Intended usage: COMMON
* Restrictions on usage: none
* Author: Daniel Fett, mail@danielfett.de
* Change Controller: IESG
* Provisional registration?  No

##  Structured Syntax Suffix Registration

This section requests registration of the "+sd-jwt" structured syntax suffix in
the "Structured Syntax Suffix" registry [@IANA.StructuredSuffix] in
the manner described in [RFC6838], which can be used to indicate that
the media type is encoded as an SD-JWT.

* Name: SD-JWT
* +suffix: +sd-jwt
* References: [[ this specification ]]
* Encoding considerations: binary; SD-JWT values are a series of base64url-encoded values (some of which may be the empty string) separated by period ('.') or tilde ('~') characters.
* Interoperability considerations: n/a
* Fragment identifier considerations: n/a
* Security considerations: See the Security Considerations section of [[ this specification ]], [@!RFC7519], and [@RFC8725].
* Contact: Daniel Fett, mail@danielfett.de
* Author/Change controller: IESG


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

<reference anchor="ISO.29100" target="https://standards.iso.org/ittf/PubliclyAvailableStandards/index.html">
  <front>
    <author fullname="ISO"></author>
    <title>ISO/IEC 29100:2011 Information technology — Security techniques — Privacy framework</title>
  </front>
</reference>

<reference anchor="VC_DATA_v2.0" target="https://www.w3.org/TR/vc-data-model-2.0/">
  <front>
    <title>Verifiable Credentials Data Model 2.0</title>
    <author fullname="Manu Sporny">
      <organization>Digital Bazaar</organization>
    </author>
    <author fullname="Orie Steele">
      <organization>Transmute</organization>
    </author>
    <author fullname="Michael B. Jones">
      <organization>Microsoft</organization>
    </author>
    <author fullname="Gabe Cohen">
      <organization>Block</organization>
    </author>
    <author fullname="Oliver Terbu">
      <organization>Spruce Systems. Inc.</organization>
    </author>
    <date day="07" month="Mar" year="2023" />
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

<reference anchor="EUDIW.ARF" target="https://digital-strategy.ec.europa.eu/en/library/european-digital-identity-wallet-architecture-and-reference-framework">
  <front>
    <author fullname="European Commission"></author>
    <title>The European Digital Identity Wallet Architecture and Reference Framework</title>
  </front>
</reference>

<reference anchor="IANA.JWS.Algorithms" target="https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms">
  <front>
    <author fullname="IANA"></author>
    <title>JSON Web Signature and Encryption Algorithms</title>
  </front>
</reference>

<reference anchor="IANA.MediaTypes" target="https://www.iana.org/assignments/media-types/media-types.xhtml">
  <front>
    <author fullname="IANA"></author>
    <title>Media Types</title>
  </front>
</reference>

<reference anchor="IANA.StructuredSuffix" target="https://www.iana.org/assignments/media-type-structured-suffix/media-type-structured-suffix.xhtml">
  <front>
    <author fullname="IANA"></author>
    <title>Structured Syntax Suffixs</title>
  </front>
</reference>

{backmatter}

# Additional Examples

All of the following examples are non-normative.

## Example 2: Handling Structured Claims {#example-simple_structured}

In this example, in contrast to [Example 1](#example-1), the Issuer decided to create a structured object for the `address` claim, allowing to separately disclose individual members of the claim.

The Issuer is using the following input claim set:

<{{examples/simple_structured/user_claims.json}}

The Issuer also decided to add decoy digests to prevent the Verifier from deducing the true number of claims.

The following payload is used for the SD-JWT:

<{{examples/simple_structured/sd_jwt_payload.json}}

The following Disclosures are created:

{{examples/simple_structured/disclosures.md}}

The following decoy digests are added:

{{examples/simple_structured/decoy_digests.md}}

The following is how a presentation of the SD-JWT that discloses only `region`
and `country` of the `address` property and without a Key Binding JWT could look like:

<{{examples/simple_structured/sd_jwt_presentation.txt}}

## Example 3 - Complex Structured SD-JWT {#example-complex-structured-sd-jwt}

In this example, an SD-JWT with a complex object is represented. The data
structures defined in OIDC4IDA [@OIDC.IDA] are used.

The Issuer is using the following input claim set:

<{{examples/complex_ekyc/user_claims.json}}

The following payload is used for the SD-JWT:

<{{examples/complex_ekyc/sd_jwt_payload.json}}

The following Disclosures are created by the Issuer:

{{examples/complex_ekyc/disclosures.md}}

The following is how a presentation of the SD-JWT
without a Key Binding JWT could look like:

<{{examples/complex_ekyc/sd_jwt_presentation.txt}}

After the validation, the Verifier will have the following data for further processing:

<{{examples/complex_ekyc/verified_contents.json}}

## Example 4a - SD-JWT-based Verifiable Credentials (SD-JWT VC)

In this example, the artifacts defined in this specification are used to represent
SD-JWT-based Verifiable Credentials (SD-JWT VC) as defined in [@I-D.terbu-sd-jwt-vc].
Person Identification Data (PID) defined in [@EUDIW.ARF] is used.

Key Binding is applied
using the Holder's public key passed in a `cnf` claim in the SD-JWT.

The Issuer is using the following input claim set:

<{{examples/arf-pid/user_claims.json}}

The following is the issued SD-JWT (with line breaks for formatting only):

<{{examples/arf-pid/sd_jwt_issuance.txt}}

The following payload is used for the SD-JWT:

<{{examples/arf-pid/sd_jwt_payload.json}}

The following Disclosures are created by the Issuer:

{{examples/arf-pid/disclosures.md}}

The following decoy digests are added:

{{examples/simple_structured/decoy_digests.md}}

The following is how a presentation of the SD-JWT with a Key Binding JWT that discloses only nationality and the fact that the person is over 18 years old could look like:

<{{examples/arf-pid/sd_jwt_presentation.txt}}

The following is the payload of a corresponding Key Binding JWT:

<{{examples/arf-pid/kb_jwt_payload.json}}

After the validation, the Verifier will have the following data for further processing:

<{{examples/arf-pid/verified_contents.json}}

## Example 4b - W3C Verifiable Credentials Data Model v2.0

In this example, the artifacts defined in this specification are used to represent a payload
that is represented as a W3C Verifiable Credentials Data Model v2.0 [@VC_DATA_v2.0].

Key Binding is applied
using the Holder's public key passed in a `cnf` claim in the SD-JWT.

The Issuer is using the following input claim set:

<{{examples/jsonld/user_claims.json}}

The following is the issued SD-JWT (with line breaks for formatting only):

<{{examples/jsonld/sd_jwt_issuance.txt}}

The following payload is used for the SD-JWT:

<{{examples/jsonld/sd_jwt_payload.json}}

The following Disclosures are created by the Issuer:

{{examples/jsonld/disclosures.md}}

The following is how a presentation of the SD-JWT with Key Binding JWT that discloses only `type`, `medicinalProductName`, `atcCode` of the vaccine, `type` of the `recipient`, `type`, `order` and `dateOfVaccination` could look like:

<{{examples/jsonld/sd_jwt_presentation.txt}}

After the validation, the Verifier will have the following data for further processing:

<{{examples/jsonld/verified_contents.json}}

## Elliptic Curve Key Used in the Examples

The following Elliptic Curve public key, represented in JWK format, can be used to validate the Issuer signatures in the above examples:

```
{
  "kty": "EC",
  "crv": "P-256",
  "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
  "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
}
```

The public key used to validate a Key Binding JWT can be found in the examples as the content of the `cnf` claim.

# Disclosure Format Considerations {#disclosure_format_considerations}

As described in (#creating_disclosures), the Disclosure structure is JSON containing salt and the
cleartext content of a claim, which is base64url encoded. The encoded value is the input used to calculate
a digest for the respective claim. The inclusion of digest value in the signed JWT ensures the integrity of
the claim value. Using encoded content as the input to the integrity mechanism is conceptually similar to the
approach in JWS and particularly useful when the content, like JSON, can have differences but be semantically
equivalent. Some further discussion of the considerations around this design decision follows.

When receiving an SD-JWT, a Verifier must
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

The two representations of the value in `family_name` are very different on the byte-level, but yield
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
specification, JSON is used and plaintext values of each Disclosure are encoded using base64url-encoding
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

   -06

   * Fix minor issues in some examples
   * Ensure claims that control validity are checked after decoding payload

   -05

   * Consolidate processing rules for Holder and Verifier
   * Add support for selective disclosure of array elements.
   * Consolidate SD-JWT terminology and format
   * Use the term Key Binding rather than Holder Binding
   * Defined the structure of the Key Binding JWT
   * Added a JWS JSON Serialization
   * Added initial IANA media type and structured suffix registration requests
   * Added recommendation for explicit typing of SD-JWTs
   * Added considerations around forwarding credentials
   * Removed Example 2b and merged the demo of decoy digests into Example 2a
   * Improved example for allowed variations in Disclosures
   * Added some text to the Abstract and Introduction to be more inclusive of JWS with JSON
   * Added some security considerations text about the scope of the Key Binding JWT
   * Aligned examples structure and used the term input claim set
   * Replaced the general SD-JWT VC example with one based on Person Identification Data (PID) from the European Digital Identity Wallet Architecture and Reference Framework
   * Added/clarified some privacy considerations in Confidentiality during Transport
   * No longer recommending a claim name for enveloped SD-JWTs
   * Mention prospective future PQ algs for JWS
   * Include the public key in the draft, which can be used to verify the issuer signature examples
   * Clarify that `_sd_alg` can only be at the top level of the SD-JWT payload
   * Externalized the SD-JWT library that generates examples
   * Attempt to improve description of security properties

   -04

   * Improve description of processing of disclosures

   -03

   * Clarify that other specifications may define enveloping multiple Combined Formats for Presentation
   * Add an example of W3C vc-data-model that uses a JSON-LD object as the claims set
   * Clarify requirements for the combined formats for issuance and presentation
   * Added overview of the Security Considerations section
   * Enhanced examples in the Privacy Considerations section
   * Allow for recursive disclosures
   * Discussion on holder binding and privacy of stored credentials
   * Add some context about SD-JWT being general-purpose despite being a product of the OAuth WG
   * More explicitly say that SD-JWTs have to be signed asymmetrically (no MAC and no `none`)
   * Make sha-256 the default hash algorithm, if the hash alg claim is omitted
   * Use ES256 instead of RS256 in examples
   * Rename and move the c14n challenges section to an appendix
   * A bit more in security considerations for Choice of a Hash Algorithm (1st & 2nd preimage resistant and not majorly truncated)
   * Remove the notational figures from the Concepts section
   * Change salt to always be a string (rather than any JSON type)
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


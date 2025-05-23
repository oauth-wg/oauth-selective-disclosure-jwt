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
organization="Authlete"
    [author.address]
    email = "mail@danielfett.de"
    uri = "https://danielfett.de/"


[[author]]
initials="K."
surname="Yasuda"
fullname="Kristina Yasuda"
organization="Keio University"
    [author.address]
    email = "kristina@sfc.keio.ac.jp"

[[author]]
initials="B."
surname="Campbell"
fullname="Brian Campbell"
organization="Ping Identity"
    [author.address]
    email = "bcampbell@pingidentity.com"


%%%

.# Abstract

This specification defines a mechanism for the selective disclosure of individual elements of a JSON data structure used as the payload of a JSON Web Signature (JWS).
The primary use case is the selective disclosure of JSON Web Token (JWT) claims.

{mainmatter}

# Introduction {#Introduction}

JSON data for exchange between systems is often secured against modification using JSON Web Signatures (JWS) [@!RFC7515].
A popular application of JWS is JSON Web Token (JWT) [@!RFC7519], a format that is often used to represent a user's identity.
An ID Token as defined in OpenID Connect [@?OpenID.Core], for example, is a JWT containing the user's claims created by the server for consumption by a relying party.
In cases where the JWT is sent immediately from the server to the relying party, as in OpenID Connect, the server can select at the time of issuance which user claims to include in the JWT, minimizing the information shared with the relying party who validates the JWT.

Another model is emerging that fully decouples the issuance of a JWT from its presentation.
In this model, a JWT containing many claims is issued to an intermediate party, who holds the JWT (the Holder).
The Holder can then present the JWT to different verifying parties (Verifiers), that each may only require a subset of the claims in the JWT.
For example, the JWT may contain claims representing both an address and a birthdate.
The Holder may elect to disclose only the address to one Verifier, and only the birthdate to a different Verifier.

Privacy principles of minimal disclosure in conjunction with this model demand a mechanism enabling selective disclosure of data elements while ensuring that Verifiers can still check the authenticity of the data provided.
This specification, Selective Disclosure for JSON Web Tokens (SD-JWT), defines such a mechanism for JSON payloads of JSON Web Signatures (JWS), with JWTs as the primary use case.

SD-JWT is based on an approach called "salted hashes": For any data element that should be selectively disclosable, the Issuer of the SD-JWT does not include the cleartext of the data in the JSON payload of the JWS structure; instead, a digest of the data takes its place.
For presentation to a Verifier, the Holder sends the signed payload along with the cleartext of those claims it wants to disclose.
The Verifier can then compute the digest of the cleartext data and confirm it is included in the signed payload.
To ensure that Verifiers cannot guess cleartext values of non-disclosed data elements, an additional salt value is used when creating the digest and sent along with the cleartext when disclosing it.

To prevent attacks in which an SD-JWT is presented to a Verifier without the Holder's consent, this specification additionally defines a mechanism for binding the SD-JWT to a key under the control of the Holder (Key Binding).
When Key Binding is enforced, a Holder has to prove possession of a private key belonging to a public key contained in the SD-JWT itself.
It usually does so by signing over a data structure containing transaction-specific data, herein defined as the Key Binding JWT.
An SD-JWT with a Key Binding JWT is called SD-JWT+KB in this specification.


## Feature Summary

This specification defines two primary data formats:

1. SD-JWT is a composite structure, consisting of a JWS plus optional disclosures, enabling selective disclosure of portions of the JWS payload. It comprises the following:
  - A format for enabling selective disclosure in nested JSON data structures,
    supporting selectively disclosable object properties (name/value pairs) and array elements
  - A format for encoding the selectively disclosable data items
  - A format extending the JWS Compact Serialization, allowing for the combined
    transport of the Issuer-signed JSON data structure and the disclosable data items
  - An alternate format extending the JWS JSON Serialization, also allowing for
    transport of the Issuer-signed JSON data structure and disclosure data

2. SD-JWT+KB is a composite structure of an SD-JWT and a cryptographic key binding that can be presented to and verified by the Verifier. It comprises the following:
  - A mechanism for associating an SD-JWT with a key pair
  - A format for a Key Binding JWT (KB-JWT) that allows proof of possession of the private key of
    the associated key pair
  - A format extending the SD-JWT format for the combined transport of the SD-JWT
    and the KB-JWT

## Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they
appear in all capitals, as shown here.

**Base64url** denotes the URL-safe base64 encoding without padding defined in
Section 2 of [@!RFC7515].

Throughout the document the term "claims" refers generally to both
object properties (name/value pairs) as well as array elements.

Selective Disclosure:
:  Process of a Holder disclosing to a Verifier a subset of claims contained in a JWT issued by an Issuer.

Selectively Disclosable JWT (SD-JWT):
:  A composite structure, consisting of an Issuer-signed JWT (JWS, [@!RFC7515]) and zero or more Disclosures, which
   supports selective disclosure as defined in this document. It can contain both regular claims and digests of selectively-disclosable claims.

Disclosure:
:  A base64url-encoded string of a JSON array that contains a salt, a claim name (present when the claim is a name/value pair and absent when the claim is an array element), and a claim value. The Disclosure is used to calculate a digest for the respective claim. The term Disclosure refers to the whole base64url-encoded string.


Key Binding:
:  Ability of the Holder to prove possession of an SD-JWT by proving
  control over a private key during the presentation. When utilizing Key Binding, an SD-JWT contains
  the public key corresponding to the private key controlled by the Holder (or a reference to this public key).

Key Binding JWT (KB-JWT):
:  A Key Binding JWT is said to "be tied to" a particular SD-JWT when its payload
  is signed using the key included in the SD-JWT payload, and the KB-JWT contains
  a hash of the SD-JWT in its `sd_hash` claim. Its format is defined in (#kb-jwt).

Selectively Disclosable JWT with Key Binding (SD-JWT+KB):
: A composite structure, comprising an SD-JWT and a Key Binding JWT tied to that SD-JWT.

Issuer:
:  An entity that creates SD-JWTs.

Holder:
: An entity that received SD-JWTs from the Issuer and has control over them. In the context of this document, the term may refer to the actual user, the supporting hardware and software in their possession, or both.

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
     Presents SD-JWT or SD-JWT+KB
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

An SD-JWT, at its core, is a digitally signed JSON document containing digests over the selectively disclosable claims with the Disclosures outside the document. Disclosures can be omitted without breaking the signature, and modifying them can be detected. Selectively disclosable claims can be individual object properties (name/value pairs) or array elements.

Each digest value ensures the integrity of, and maps to, the respective Disclosure.  Digest values are calculated using a hash function over the Disclosures, each of which contains a cryptographically secure random salt, the claim name (only when the claim is an object property), and the claim value. The Disclosures are sent to the Holder with the SD-JWT in the format defined in (#data_formats).
When presenting an SD-JWT to a Verifier, the Holder only includes the Disclosures for the claims that it wants to reveal to that Verifier.

An SD-JWT MAY also contain cleartext claims that are always disclosed to the Verifier.

## Disclosing to a Verifier

To disclose to a Verifier a subset of the SD-JWT claim values, a Holder sends only the Disclosures of those selectively released claims to the Verifier as part of the SD-JWT.

## Optional Key Binding

Key Binding is an optional feature. When Key Binding is required by the use case, the SD-JWT MUST contain information about the key material controlled by the Holder.

> Note: How the public key is included in SD-JWT is described in (#key_binding).

When a Verifier requires Key Binding, the Holder presents an SD-JWT+KB, consisting of an SD-JWT as well as a Key Binding JWT tied to that SD-JWT.
The Key Binding JWT encodes a signature by the Holder's private key over

* a hash of the SD-JWT,
* a nonce to ensure the freshness of the signature, and
* an audience value to indicate the intended Verifier for the document.

Details of the format of Key Binding JWTs are described in (#kb-jwt).

## Verification

At a high level, the Verifier

 * receives either an SD-JWT or an SD-JWT+KB from the Holder,
 * verifies the signature on the SD-JWT (or the SD-JWT inside the SD-JWT+KB) using the Issuer's public key,
 * verifies the signature on the KB-JWT using the public key included (or referenced) in the SD-JWT, if the Verifier's policy requires Key Binding, and
 * calculates the digests over the Holder-Selected Disclosures and verifies that each digest is contained in the SD-JWT.

The detailed algorithm is described in (#verifier_verification).

# SD-JWT and SD-JWT+KB Data Formats {#data_formats}

An SD-JWT is composed of

* an Issuer-signed JWT, and
* zero or more Disclosures.

An SD-JWT+KB is composed of

* an SD-JWT (i.e., an Issuer-signed JWT and zero or more Disclosures), and
* a Key Binding JWT.

The Issuer-signed JWT, Disclosures, and Key Binding JWT are explained in
(#iss-signed-jwt), (#creating_disclosures), and (#kb-jwt) respectively.

The compact serialized format for the SD-JWT is the concatenation of each part delineated with a single tilde ('~') character as follows:

```
<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~
```

The order of the concatenated parts MUST be the Issuer-signed JWT,
a tilde character, zero or more Disclosures each followed by a tilde character,
and lastly the optional Key Binding JWT.
In the case that there is no Key Binding JWT, the last element MUST be an empty
string and the last separating tilde character MUST NOT be omitted.

The serialized format for an SD-JWT+KB extends the SD-JWT format by concatenating a Key Binding JWT.

```
<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~<KB-JWT>
```

The two formats can be distinguished by the final `~` character that is present
on an SD-JWT.  A Verifier that expects an SD-JWT MUST verify that the final
tilde-separated component is empty.  A Verifier that expects an SD-JWT+KB MUST verify
that its final tilde-separated component is a valid KB-JWT.

The Disclosures are linked to the Issuer-signed JWT through the
digest values included therein.

When issuing to a Holder, the Issuer includes all the relevant Disclosures in the SD-JWT.

When presenting to a Verifier, the Holder sends only the selected set of the Disclosures in the SD-JWT.

The Holder MAY send any subset of the Disclosures to the Verifier, i.e.,
none, some, or all Disclosures. For data that the Holder does not want to reveal
to the Verifier, the Holder MUST NOT send Disclosures or reveal the salt values in any
other way. A Holder MUST NOT send a Disclosure that was not included in the issued
SD-JWT or send a Disclosure more than once.

To further illustrate the SD-JWT format, the following examples show a few different
SD-JWT permutations, both with and without various constituent parts.


An SD-JWT without Disclosures:
```
<Issuer-signed JWT>~
```

An SD-JWT with Disclosures:
```
<Issuer-signed JWT>~<Disclosure 1>~<Disclosure N>~
```

An SD-JWT+KB without Disclosures:
```
<Issuer-signed JWT>~<KB-JWT>
```

An SD-JWT+KB with Disclosures:
```
<Issuer-signed JWT>~<Disclosure 1>~<Disclosure N>~<KB-JWT>
```

As an alternative illustration of the SD-JWT format, ABNF [@?RFC5234] for the
SD-JWT, SD-JWT+KB, and various constituent parts is provided here (for those who celebrate):
```abnf
ALPHA = %x41-5A / %x61-7A ; A-Z / a-z
DIGIT = %x30-39 ; 0-9
BASE64URL = 1*(ALPHA / DIGIT / "-" / "_")
JWT = BASE64URL "." BASE64URL "." BASE64URL
DISCLOSURE = BASE64URL
SD-JWT = JWT "~" *(DISCLOSURE "~")
KB-JWT = JWT
SD-JWT-KB = SD-JWT KB-JWT
```

## Issuer-signed JWT {#iss-signed-jwt}

An SD-JWT has a JWT component that MUST be signed using the Issuer's private
key. It MUST NOT use the `none` algorithm.

The payload of an SD-JWT is a JSON object according to the following rules:

 1. The payload MAY contain the `_sd_alg` key described in (#hash_function_claim).
 2. The payload MAY contain one or more digests of Disclosures to enable selective disclosure of the respective claims, created and formatted as described in (#creating_disclosures).
 3. The payload MAY contain one or more decoy digests to obscure the actual number of claims in the SD-JWT, created and formatted as described in (#decoy_digests).
 4. The payload MAY contain one or more permanently disclosed claims.
 5. The payload MAY contain the Holder's public key(s) or reference(s) thereto, as explained in (#key_binding).
 6. The payload MAY contain further claims such as `iss`, `iat`, etc. as defined or required by the application using SD-JWTs.
 7. The payload MUST NOT contain the claims `_sd` or `...` except for the purpose of conveying digests as described in (#embedding_object_properties) and (#embedding_array_elements) respectively below.

The same digest value MUST NOT appear more than once in the SD-JWT.

Application and profiles of SD-JWT SHOULD be explicitly typed. See (#explicit_typing) for more details.

It is the Issuer who decides which claims are selectively disclosable by the Holder and which are not. Claims MAY be included as plaintext as well, e.g., if hiding the particular claims from the Verifier is not required in the intended use case. See (#sd-validity-claims) for considerations on making validity-controlling claims such as `exp` selectively disclosable.

Claims that are not selectively disclosable are included in the SD-JWT in plaintext just as they would be in any other JSON structure.


### Hash Function Claim {#hash_function_claim}

The claim `_sd_alg` indicates the hash algorithm used by the Issuer to generate
the digests as described in (#creating_disclosures). When used, this claim MUST
appear at the top level of the SD-JWT payload. It
MUST NOT be used in any object nested within the payload. If the  `_sd_alg`
claim is not present at the top level, a default value of `sha-256` MUST be used.

This claim value is a case-sensitive string with the hash algorithm identifier.
The hash algorithm identifier MUST be a hash algorithm value from the "Hash Name
String" column in the IANA "Named Information Hash Algorithm" registry
[@IANA.Hash.Algorithms] or a value defined in another specification and/or
profile of this specification.

To promote interoperability, implementations MUST support the `sha-256` hash
algorithm.

See (#security_considerations) for requirements regarding entropy of the salt,
minimum length of the salt, and choice of a hash algorithm.

### Key Binding {#key_binding}

If the Issuer wants to enable Key Binding, it includes a public key
associated with the Holder, or a reference thereto, using the `cnf` claim as defined in [@!RFC7800].
The `jwk` confirmation method, as defined in Section 3.2 of [@!RFC7800], is
suggested for doing so, however, other confirmation methods can be used.

> Note that, as was stated in [@!RFC7800],
if an application needs to represent multiple proof-of-possession
keys in the same SD-JWT, one way to achieve this is to use other
claim names, in addition to `cnf`, to hold the additional proof-of-possession key information.

It is out of the scope of this document to describe how the Holder key pair is
established. For example, the Holder MAY create a key pair and provide a public key to the Issuer,
the Issuer MAY create the key pair for the Holder, or
Holder and Issuer MAY use pre-established key material.

> Note: The examples throughout this document use the `cnf` claim with the `jwk` member to include
the raw public key by value in SD-JWT.

## Disclosures {#creating_disclosures}

Disclosures are created differently depending on whether a claim is an object property (name/value pair) or an array element.

 * For a claim that is an object property, the Issuer creates a Disclosure as described in (#disclosures_for_object_properties).
 * For a claim that is an array element, the Issuer creates a Disclosure as described in (#disclosures_for_array_elements).

### Disclosures for Object Properties {#disclosures_for_object_properties}
For each claim that is an object property and that is to be made selectively disclosable, the Issuer MUST create a Disclosure as follows:

 * Create a JSON array of three elements in this order:
   1. A salt value. MUST be a string. See (#salt-entropy) for security considerations. It is RECOMMENDED to base64url-encode a minimum of 128 bits of cryptographically secure random data, producing a string. The salt value MUST be unique for each claim that is to be selectively disclosed. The Issuer MUST NOT reveal the salt value to any party other than the Holder.
   2. The claim name, or key, as it would be used in a regular JWT payload. It MUST be a string and MUST NOT be `_sd`, `...`, or a claim name existing in the object as a permanently disclosed claim.
   3. The claim value, as it would be used in a regular JWT payload. The value can be of any type that is allowed in JSON, including numbers, strings, booleans, arrays, null, and objects.
 * base64url-encode the UTF-8 byte sequence of the JSON array. This string is the Disclosure.

> Note: The order was decided based on readability considerations: salts have a
constant length within the SD-JWT, claim names would be around the same length
all the time, and claim values would vary in size, potentially being large
objects.

The following example illustrates the steps described above.

The array is created as follows:
```json
["_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius"]
```

The resulting Disclosure is: `WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0`

Note that variations in whitespace, encoding of Unicode characters, ordering of object properties, etc., are allowed
in the JSON representation and no canonicalization needs to be performed before base64url-encoding because the digest is calculated over the base64url-encoded value itself.
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

However, the digest is calculated over the respective base64url-encoded value itself, which effectively signs the variation chosen by the Issuer and makes it immutable in the context of the particular SD-JWT.

See (#disclosure_format_considerations) for some further considerations on the Disclosure format approach.

### Disclosures for Array Elements {#disclosures_for_array_elements}

For each claim that is an array element and that is to be made selectively disclosable, the Issuer MUST create a Disclosure as follows:

 * The array MUST contain two elements in this order:
   1. The salt value as described in (#disclosures_for_object_properties).
   2. The array element that is to be hidden. This value can be of any type that is allowed in JSON, including numbers, strings, booleans, arrays, and objects.

The Disclosure string is created by base64url-encoding the UTF-8 byte sequence of the resulting JSON array as described in (#disclosures_for_object_properties). The same considerations regarding
variations in the result of the JSON encoding apply.

For example, a Disclosure for the second element of the `nationalities` array in the following JWT Claims Set:

```json
{
  "nationalities": ["DE", "FR", "US"]
}
```

could be created by first creating the following array:

```json
["lklxF5jMYlGTPUovMNIvCA", "FR"]
```

The resulting Disclosure would be: `WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0`

> Note that the size of an array alone can potentially reveal unintended information.
The use of decoys, as described in (#decoy_digests), to consistently pad the size of an array can help obscure
the actual number of elements present in any particular instance.

### Hashing Disclosures {#hashing_disclosures}

For embedding references to the Disclosures in the SD-JWT, each Disclosure is hashed using the hash algorithm specified in the `_sd_alg` claim described in (#hash_function_claim), or SHA-256 if no algorithm is specified. The resulting digest is then included in the SD-JWT payload instead of the original claim value, as described next.

The digest MUST be taken over the US-ASCII bytes of the base64url-encoded value that is the Disclosure. This follows the convention in JWS [@!RFC7515] and JWE [@RFC7516]. The bytes of the digest MUST then be base64url-encoded.

It is important to note that:

 * The input to the hash function MUST be the base64url-encoded Disclosure, not the bytes encoded by the base64url string.
 * The bytes of the output of the hash function MUST be base64url-encoded, and are not the bytes making up the (sometimes used) hex representation of the bytes of the digest.

For example, the base64url-encoded SHA-256 digest of the Disclosure
`WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0`
for the `family_name` claim from (#disclosures_for_object_properties) above is
`X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0`.


### Embedding Disclosure Digests in SD-JWTs {#embedding_disclosure_digests}

For selectively disclosable claims, the digests of the Disclosures are embedded into the Issuer-signed JWT instead of the claims themselves. The precise way of embedding depends on whether a claim is an object property (name/value pair) or an array element.

 * For a claim that is an object property, the Issuer embeds a Disclosure digest as described in (#embedding_object_properties).
 * For a claim that is an array element, the Issuer creates a Disclosure digest as described in (#embedding_array_elements).

#### Object Properties {#embedding_object_properties}

Digests of Disclosures for object properties are added to an array under the new
key `_sd` in the object. The `_sd` key MUST refer to an array of strings, each
string being a digest of a Disclosure or a decoy digest as described in (#decoy_digests).
An `_sd` key can be present at any level of the JSON object hierarchy, including the top-level,
nested deeper as described in (#nested_data), or in recursive disclosures as described in (#recursive_disclosures).

The array MAY be empty in case the Issuer decided not to selectively disclose
any of the claims at that level. However, it is RECOMMENDED to omit the `_sd`
key in this case to save space.

The Issuer MUST hide the original order of the claims in the array. To ensure
this, it is RECOMMENDED to shuffle the array of hashes, e.g., by sorting it
alphanumerically or randomly, after potentially adding
decoy digests as described in (#decoy_digests). The precise method does not matter as long as it
does not depend on the original order of elements.

For example, using the digest of the Disclosure from (#hashing_disclosures),
the Issuer could create the following SD-JWT payload to make `family_name`
selectively disclosable:

```json
{
  "given_name": "Alice",
  "_sd": ["X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"]
}
```

#### Array Elements {#embedding_array_elements}

Digests of Disclosures for array elements are added to the array in the same
position as the original claim value in the array. For each digest, an object
of the form `{"...": "<digest>"}` is added to the array. The key MUST always be the
string `...` (three dots). The value MUST be the digest of the Disclosure created as
described in (#hashing_disclosures). There MUST NOT be any other keys in the
object. Note that the string `...` was chosen because the ellipsis character, typically entered as three period characters, is commonly used in places where content is omitted from the present context.

For example, using the digest of the array element Disclosure created above in (#disclosures_for_array_elements),
the Issuer could create the following SD-JWT payload to make the second element
of the `nationalities` array selectively disclosable:

```json
{
  "nationalities":
    ["DE", {"...":"w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"}, "US"]
}
```

As described in (#verifier_verification), Verifiers ignore all selectively
disclosable array elements for which they did not receive a Disclosure. In the
example above, the verification process would output an array with only one
element unless a matching Disclosure for the second element is received.

### Decoy Digests {#decoy_digests}

An Issuer MAY add additional digests to the SD-JWT payload that are not associated with
any claim.  The purpose of such "decoy" digests is to make it more difficult for
an adversary to see the original number of claims or array elements contained in the SD-JWT. Decoy
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

### Recursive Disclosures {#recursive_disclosures}

The algorithms above are compatible with "recursive disclosures", in which one
selectively disclosed field reveals the existence of more selectively
disclosable fields.  For example, consider the following JSON structure:

```json
{
    "family_name": "Möbius",
    "nationalities": ["DE", "FR", "UK"]
}
```

When the Holder has multiple nationalities, the issuer may wish to conceal
the presence of any statement regarding nationalities while also allowing the
holder to reveal each of those nationalities individually.
This can be accomplished by first making the entries within the "nationalities"
array selectively disclosable, and then making the whole "nationalities" field
selectively disclosable.

The following shows each of the entries within the "nationalities" array being made selectively disclosable:

``` ascii-art
{
    "family_name": "Möbius",
    "nationalities": [
        { "...": "PmnlrRjhLcwf8zTDdK15HVGwHtPYjddvD362WjBLwro" }
        { "...": "r823HFN6Ba_lpSANYtXqqCBAH-TsQlIzfOK0lRAFLCM" },
        { "...": "nP5GYjwhFm6ESlAeC4NCaIliW4tz0hTrUeoJB3lb5TA" }
    ]
}

Content of Disclosures:
PmnlrRj... = ["16_mAd0GiwaZokU26_0i0h","DE"]
r823HFN... = ["fn9fN0rD-fFs2n303ZI-0c","FR"]
nP5GYjw... = ["YIKesqOkXXNzMQtsX_-_lw","UK"]
```

Followed by making the whole "nationalities" array selectively disclosable:

``` ascii-art
{
    "family_name": "Möbius",
    "_sd": [ "5G1srw3RG5W4pVTwSsYxeOWosRBbzd18ZoWKkC-hBL4" ]
}

Content of Disclosures:
PmnlrRj... = ["16_mAd0GiwaZokU26_0i0h","DE"]
r823HFN... = ["fn9fN0rD-fFs2n303ZI-0c","FR"]
nP5GYjw... = ["YIKesqOkXXNzMQtsX_-_lw","UK"]
5G1srw3... = ["4drfeTtSUK3aY_-PF12gcX","nationalities",
    [
        { "...": "PmnlrRjhLcwf8zTDdK15HVGwHtPYjddvD362WjBLwro" },
        { "...": "r823HFN6Ba_lpSANYtXqqCBAH-TsQlIzfOK0lRAFLCM" },
        { "...": "nP5GYjwhFm6ESlAeC4NCaIliW4tz0hTrUeoJB3lb5TA" }
    ]
]
```



With this set of disclosures, the holder could include the disclosure with hash
`PmnlrRj...` to disclose only the "DE" nationality, or include both `PmnlrRj...`
and `r823HFN...` to disclose both the "DE" and "FR" nationalities, but hide the
"UK" nationality. In either case, the holder would also need to include the
disclosure with hash `5G1srw3...` to disclose the `nationalities` field that
contains the respective elements.

Note that making recursive redactions introduces dependencies between the
disclosure objects in an SD-JWT.  The `r823HFN...` disclosure cannot be used
without the `5G1srw3...` disclosure; since a Verifier would not have a matching
hash that would tell it where the content of the `r823HFN...` disclosure should
be inserted.  If a disclosure object is included in an SD-JWT, then the SD-JWT
MUST include any other disclosure objects necessary to process the first
disclosure object.  In other words, any disclosure object in an SD-JWT must
"connect" to the claims in the issuer-signed JWT, possibly via an intermediate
disclosure object.  In the above example, it would be illegal to include any one
of the `PmnlrRj...`, `r823HFN...`, `nP5GYjw..` disclosure objects without also
including the `5G1srw3...` disclosure object.

## Key Binding JWT {#kb-jwt}

This section defines the Key Binding JWT, which encodes a
signature over an SD-JWT by the Holder's private key.

The Key Binding JWT MUST be a JWT according to [@!RFC7519] and its payload MUST contain the following elements:

* in the JOSE header,
    * `typ`: REQUIRED. MUST be `kb+jwt`, which explicitly types the Key Binding JWT as recommended in Section 3.11 of [@!RFC8725].
    * `alg`: REQUIRED. A digital signature algorithm identifier such as per IANA "JSON Web Signature and Encryption Algorithms" registry. It MUST NOT be `none`.
* in the JWT payload,
    * `iat`: REQUIRED. The value of this claim MUST be the time at which the Key Binding JWT was issued using the syntax defined in [@!RFC7519].
    * `aud`: REQUIRED. The intended receiver of the Key Binding JWT. How the value is represented is up to the protocol used and out of scope of this specification.
    * `nonce`: REQUIRED. Ensures the freshness of the signature or its binding to the given transaction. The value type of this claim MUST be a string. How this value is obtained is up to the protocol used and out of scope of this specification.
    * `sd_hash`: REQUIRED. The base64url-encoded hash value over the Issuer-signed JWT and the selected Disclosures as defined below.

The general extensibility model of JWT means that additional claims and header parameters can be added to the Key Binding JWT.
However, unless there is a compelling reason, this SHOULD be avoided, as it may harm interoperability and burden conceptual integrity.

### Binding to an SD-JWT {#integrity-protection-of-the-presentation}

The hash value in the `sd_hash` claim binds the KB-JWT to the specific SD-JWT.
The `sd_hash` value MUST be taken over the US-ASCII bytes of the
encoded SD-JWT, i.e.,
the Issuer-signed JWT, a tilde character, and zero or more Disclosures selected
for presentation to the Verifier, each followed by a tilde character:

```
<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~
```

The bytes of the digest MUST then be base64url-encoded.

The same hash algorithm as for the Disclosures MUST be used (defined by
the `_sd_alg` element in the Issuer-signed JWT or the default value, as defined
in (#hash_function_claim)).

### Validating the Key Binding JWT

Whether to require Key Binding is up to the Verifier's policy, based on the set
of trust requirements such as trust frameworks it belongs to. See
(#key_binding_security) for security considerations.

If the Verifier requires Key Binding, the Verifier MUST ensure that the key with which it validates the signature on
the Key Binding JWT is the key specified in the SD-JWT as the Holder's public
key.  For example, if the SD-JWT contains a `cnf` value with a `jwk` member, the
Verifier would parse the provided JWK and use it to verify the Key Binding JWT.

Details of the Validation process are defined in (#verifier_verification).


# Example SD-JWT {#main-example}

In this example, a simple SD-JWT is demonstrated. This example is split into issuance and presentation.

> Note: Throughout the examples in this document, line breaks had to be added to
JSON strings and base64-encoded strings to adhere to the 72-character limit for
lines in RFCs and for readability. JSON does not allow line breaks within strings.

## Issuance

The following data about the user comprises the input JWT Claims Set used by the Issuer:

<{{examples/simple/user_claims.json}}

In this example, the following decisions were made by the Issuer in constructing the SD-JWT:

* The `nationalities` array is always visible, but its contents are selectively disclosable.
* The `sub` element as well as essential verification data (`iss`, `exp`, `cnf`, etc.) are always visible.
* All other claims are selectively disclosable.
* For `address`, the Issuer is using a flat structure, i.e., all the claims
  in the `address` claim can only be disclosed in full. Other options are
  discussed in (#nested_data).

The following payload is used for the SD-JWT:

<{{examples/simple/sd_jwt_payload.json}}

The respective Disclosures, created by the Issuer, are listed below.
In the text below and in other locations in this specification,
the label "SHA-256 Hash:" is used as a shorthand for the label "Base64url-Encoded SHA-256 Hash:".

{{examples/simple/disclosures.md}}

The payload is then signed by the Issuer to create the following Issuer-signed JWT:

<{{examples/simple/sd_jwt_jws_part.txt}}

Adding the Disclosures produces the SD-JWT:

<{{examples/simple/sd_jwt_issuance.txt}}

## Presentation

The following non-normative example shows an SD-JWT+KB as
it would be sent from the Holder to the Verifier. Note that it consists of six
tilde-separated parts, with the Issuer-signed JWT as shown above in the beginning,
four Disclosures (for the claims `given_name`, `family_name`, `address`, and one of the
`nationalities`) in the middle, and the Key Binding JWT as the last element.

<{{examples/simple/sd_jwt_presentation.txt}}

The following Key Binding JWT payload was created and signed for this presentation by the Holder:

<{{examples/simple/kb_jwt_payload.json}}

If the Verifier did not require Key Binding, then the Holder could have
presented the SD-JWT with selected Disclosures directly, instead of encapsulating it in
an SD-JWT+KB.

After validation, the Verifier will have the following processed SD-JWT payload available for further handling:

<{{examples/simple/verified_contents.json}}

# Considerations on Nested Data in SD-JWTs {#nested_data}

Being JSON, an object in an SD-JWT payload MAY contain name/value pairs where the value is another object or objects MAY be elements in arrays. In SD-JWT, the Issuer decides for each claim individually, on each level of the JSON, whether the claim should be selectively disclosable or not. This choice can be made on each level independent of whether keys higher in the hierarchy are selectively disclosable.

From this it follows that the `_sd` key containing digests MAY appear multiple
times in an SD-JWT, and likewise, there MAY be multiple arrays within the
hierarchy with each having selectively disclosable elements. Digests of
selectively disclosable claims MAY even appear within other Disclosures.

The following examples illustrate some of the options an Issuer has. It is up to the Issuer to decide which structure to use, depending on, for example, the expected use cases for the SD-JWT, requirements for privacy, size considerations, or operating environment requirements. For more examples with nested structures, see (#example-simple_structured) and (#example-complex-structured-sd-jwt).

The following input JWT Claims Set is used as an example throughout this section:

<{{examples/address_only_flat/user_claims.json}}

> Note: The following examples of the structures are non-normative and are not intended to
represent all possible options. They are also not meant to define or restrict
how `address` can be represented in an SD-JWT.

## Example: Flat SD-JWT

The Issuer can decide to treat the `address` claim as a block that can either be disclosed completely or not at all. The following example shows that in this case, the entire `address` claim is treated as an object in the Disclosure.

<{{examples/address_only_flat/sd_jwt_payload.json}}

The Issuer would create the following Disclosure referenced by the one hash in the SD-JWT:

{{examples/address_only_flat/disclosures.md}}

## Example: Structured SD-JWT

The Issuer may instead decide to make the `address` claim contents selectively disclosable individually:

<{{examples/address_only_structured/sd_jwt_payload.json}}

In this case, the Issuer would use the following data in the Disclosures for the `address` sub-claims:

{{examples/address_only_structured/disclosures.md}}

The Issuer may also make one sub-claim of `address` permanently disclosed and hide only the other sub-claims:

<{{examples/address_only_structured_one_open/sd_jwt_payload.json}}

In this case, there would be no Disclosure for `country`, since it is provided in the clear.

## Example: SD-JWT with Recursive Disclosures

The Issuer may also decide to make the `address` claim contents selectively disclosable recursively, i.e., the `address` claim is made selectively disclosable as well as its sub-claims:

<{{examples/address_only_recursive/sd_jwt_payload.json}}

The Issuer creates Disclosures first for the sub-claims and then includes their digests in the Disclosure for the `address` claim:

{{examples/address_only_recursive/disclosures.md}}

# Verification and Processing {#verification}

## Verification of the SD-JWT {#sd_jwt_verification}

Upon receiving an SD-JWT, either directly or as a component of an SD-JWT+KB, a Holder
or a Verifier needs to ensure that:

 * the Issuer-signed JWT is valid, i.e., it is signed by the Issuer, the signature is valid, it is not expired, it is not suspended or revoked, etc., and
 * all Disclosures are valid and correspond to a respective digest value in the Issuer-signed JWT (directly in the payload or recursively included in the contents of other Disclosures).

The Holder or the Verifier MUST perform the following (or equivalent) steps when receiving
an SD-JWT to validate the SD-JWT and extract the payload:

1. Separate the SD-JWT into the Issuer-signed JWT and the Disclosures (if any).
2. Validate the Issuer-signed JWT:
    1. Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [@!RFC8725], Sections 3.1 and 3.2 for details. The `none` algorithm MUST NOT be accepted.
    2. Validate the signature over the Issuer-signed JWT per Section 5.2 of [@!RFC7515].
    3. Validate the Issuer and that the signing key belongs to this Issuer.
    5. Check that the `_sd_alg` claim value is understood and the hash algorithm is deemed secure (see (#hash_function_claim)).
3. Process the Disclosures and embedded digests in the Issuer-signed JWT as follows:
    1. For each Disclosure provided:
        1. Calculate the digest over the base64url-encoded string as described in (#hashing_disclosures).
    2. (*) Identify all embedded digests in the Issuer-signed JWT as follows:
        1. Find all objects having an `_sd` key that refers to an array of strings.
        2. Find all array elements that are objects with one key, that key being `...` and referring to a string.
    3. (**) For each embedded digest found in the previous step:
        1. Compare the value with the digests calculated previously and find the matching Disclosure. If no such Disclosure can be found, the digest MUST be ignored.
        2. If the digest was found in an object's `_sd` key:
            1. If the contents of the respective Disclosure is not a JSON array of three elements (salt, claim name, claim value), the SD-JWT MUST be rejected.
            2. If the claim name is `_sd` or `...`, the SD-JWT MUST be rejected.
            3. If the claim name already exists at the level of the `_sd` key, the SD-JWT MUST be rejected.
            4. Insert, at the level of the `_sd` key, a new claim using the claim name and claim value from the Disclosure.
            5. Recursively process the value using the steps described in (*) and (**).
        3. If the digest was found in an array element:
            1. If the contents of the respective Disclosure is not a JSON array of two elements (salt, value), the SD-JWT MUST be rejected.
            2. Replace the array element with the value from the Disclosure.
            3. Recursively process the value using the steps described in (*) and (**).
    4. Remove all array elements for which the digest was not found in the previous step.
    5. Remove all `_sd` keys and their contents from the Issuer-signed JWT payload. If this results in an object with no properties, it should be represented as an empty object `{}`.
    6. Remove the claim `_sd_alg` from the SD-JWT payload.
4. If any digest value is encountered more than once in the Issuer-signed JWT payload (directly or recursively via other Disclosures), the SD-JWT MUST be rejected.
5. If any Disclosure was not referenced by digest value in the Issuer-signed JWT (directly or recursively via other Disclosures), the SD-JWT MUST be rejected.
6. Check that the SD-JWT is valid using claims such as `nbf`, `iat`, and `exp` in the processed payload. If a required validity-controlling claim is missing (see (#sd-validity-claims)), the SD-JWT MUST be rejected.

If any step fails, the SD-JWT is not valid, and processing MUST be aborted. Otherwise, the JSON document resulting from the preceding processing and verification steps, herein referred to as the processed SD-JWT payload, can be made available to the application to be used for its intended purpose.

> Note that these processing steps do not yield any guarantees to the Holder about having received a complete set of Disclosures. That is, for some digest values in the Issuer-signed JWT (which are not decoy digests) there may be no corresponding Disclosures, for example, if the message from the Issuer was truncated.
It is up to the Holder how to maintain the mapping between the Disclosures and the plaintext claim values to be able to display them to the user when needed.


## Processing by the Holder  {#holder_verification}

The Issuer provides the Holder with an SD-JWT, not an SD-JWT+KB.  If the Holder
receives an SD-JWT+KB, it MUST be rejected.

When receiving an SD-JWT, the Holder MUST do the following:

 1. Process the SD-JWT as defined in (#sd_jwt_verification) to validate it and extract the payload.
 2. Ensure that the contents of claims in the payload are acceptable (depending on the application; for example, check that any values the Holder can check are correct).

For presentation to a Verifier, the Holder MUST perform the following (or equivalent) steps (in addition to the checks described in (#sd_jwt_verification) performed after receiving the SD-JWT):

 1. Decide which Disclosures to release to the Verifier, obtaining proper consent if necessary.
 2. Verify that each selected Disclosure satisfies one of the two following conditions:
    1. The hash of the Disclosure is contained in the Issuer-signed JWT claims
    2. The hash of the Disclosure is contained in the claim value of another selected Disclosure
 3. Assemble the SD-JWT, including the Issuer-signed JWT and the selected Disclosures (see (#data_formats) for the format).
 4. If Key Binding is not required:
    1. Send the SD-JWT to the Verifier.
 5. If Key Binding is required:
    1. Create a Key Binding JWT tied to the SD-JWT.
    2. Assemble the SD-JWT+KB by concatenating the SD-JWT and the Key Binding JWT.
    3. Send the SD-JWT+KB to the Verifier.

## Verification by the Verifier  {#verifier_verification}

Upon receiving a presentation from a Holder, in the form of either an SD-JWT or
an SD-JWT+KB, in addition to the checks described in (#sd_jwt_verification), Verifiers need to ensure that

 * if Key Binding is required, then the Holder has provided an SD-JWT+KB, and
 * the Key Binding JWT is signed by the Holder and valid.

To this end, Verifiers MUST follow the following steps (or equivalent):

1. Determine if Key Binding is to be checked according to the Verifier's policy
   for the use case at hand. This decision MUST NOT be based on whether
   a Key Binding JWT is provided by the Holder or not. Refer to (#key_binding_security) for
   details.
2. If Key Binding is required and the Holder has provided an SD-JWT (without Key Binding), the Verifier MUST reject the presentation.
3. If the Holder has provided an SD-JWT+KB, parse it into an SD-JWT and a Key Binding JWT.
4. Process the SD-JWT as defined in (#sd_jwt_verification) to validate the presentation and extract the payload.
5. If Key Binding is required:
    1. Determine the public key for the Holder from the SD-JWT (see (#key_binding)).
    2. Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [@!RFC8725], Sections 3.1 and 3.2 for details. The `none` algorithm MUST NOT be accepted.
    3. Validate the signature over the Key Binding JWT per Section 5.2 of [@!RFC7515].
    4. Check that the `typ` of the Key Binding JWT is `kb+jwt` (see (#kb-jwt)).
    5. Check that the creation time of the Key Binding JWT, as determined by the `iat` claim, is within an acceptable window.
    6. Determine that the Key Binding JWT is bound to the current transaction and was created for this Verifier (replay detection) by validating `nonce` and `aud` claims.
    7. Calculate the digest over the Issuer-signed JWT and Disclosures as defined in (#integrity-protection-of-the-presentation) and verify that it matches the value of the `sd_hash` claim in the Key Binding JWT.
    8. Check that the Key Binding JWT is a valid JWT in all other respects, per [@!RFC7519] and [@!RFC8725].

If any step fails, the presentation is not valid and processing MUST be aborted.

Otherwise, the processed SD-JWT payload can be passed to the application to be used for the intended purpose.

# JWS JSON Serialization {#json_serialization}

This section describes an alternative format for SD-JWTs and SD-JWT+KBs using the JWS JSON
Serialization from [@!RFC7515]. Supporting this format is OPTIONAL.

## New Unprotected Header Parameters {#json_serialization_unprotected_headers}

For both the General and Flattened JSON Serialization, the SD-JWT or SD-JWT+KB is represented
as a JSON object according to Section 7.2 of [@!RFC7515]. The following new
unprotected header parameters are defined:

 * `disclosures`: An array of strings where each element is an individual
   Disclosure as described in (#creating_disclosures).
 * `kb_jwt`: Present only in an SD-JWT+KB, the Key Binding JWT as described in (#kb-jwt).


In an SD-JWT+KB, `kb_jwt` MUST be present when using the JWS JSON Serialization,
and the digest in the `sd_hash` claim MUST be taken over the SD-JWT as described
in (#integrity-protection-of-the-presentation). This means that even when using
the JWS JSON Serialization, the representation as a regular SD-JWT Compact Serialization MUST be
created temporarily to calculate the digest. In detail, the SD-JWT Compact Serialization part is built
by concatenating the protected header, the payload, and the signature of the JWS
JSON serialized SD-JWT using a `.` character as a separator, and using the
Disclosures from the `disclosures` member of the unprotected header.

Unprotected headers other than `disclosures` are not covered by the digest, and
therefore, as usual, are not protected against tampering.

## Flattened JSON Serialization

In case of the Flattened JSON Serialization, there is only one unprotected
header.

The following is a non-normative example of a JWS JSON serialized SD-JWT as
issued using the Flattened JSON Serialization:

<{{examples/json_serialization_flattened/sd_jwt_issuance.json}}

The following is an SD-JWT+KB with two Disclosures:

<{{examples/json_serialization_flattened/sd_jwt_presentation.json}}

## General JSON Serialization

In case of the General JSON Serialization, there are multiple unprotected
headers (one per signature). If present, `disclosures` and `kb_jwt`, MUST be
included in the first unprotected header and MUST NOT be present in any
following unprotected headers.

The following is a non-normative example of a presentation of a JWS JSON
serialized SD-JWT including a Key Binding JWT using the General JSON
Serialization:

<{{examples/json_serialization_general/sd_jwt_presentation.json}}

## Verification of the JWS JSON Serialized SD-JWT

Verification of the JWS JSON serialized SD-JWT follows the rules defined in
(#verification), except for the following aspects:

 * The SD-JWT or SD-JWT+KB does not need to be split into component parts and the Disclosures
   can be found in the `disclosures` member of the unprotected header.
 * To verify the digest in `sd_hash` in the Key Binding JWT of an SD-JWT+KB, the Verifier MUST
   assemble the string to be hashed as described in
   (#json_serialization_unprotected_headers).

# Security Considerations {#security_considerations}

Security considerations in this section help achieve the following properties:

**Selective Disclosure:** An adversary in the role of the Verifier cannot obtain
information from an SD-JWT about any claim name or claim value that was not
explicitly disclosed by the Holder unless that information can be derived from
other disclosed claims or sources other than the presented SD-JWT.

**Integrity:** A malicious Holder cannot modify names or values of selectively disclosable claims without detection by the Verifier.

Additionally, as described in (#key_binding_security), the application of Key Binding can ensure that the presenter of an SD-JWT credential is the Holder of the credential.

## Mandatory Signing of the Issuer-signed JWT {#sec-is-jwt}

The JWT MUST be signed by the Issuer to protect integrity of the issued
claims. An attacker can modify or add claims if this JWT is not signed (e.g.,
change the "email" attribute to take over the victim's account or add an
attribute indicating a fake academic qualification).

The Verifier MUST always check the signature of the Issuer-signed JWT to ensure that it
has not been tampered with since the issuance. The Issuer-signed JWT MUST be rejected if the signature cannot be verified.

The security of the Issuer-signed JWT depends on the security of the signature algorithm.
Any of the JWS asymmetric digital signature algorithms registered in [@IANA.JWS.Algorithms]
that meet the security requirements described in the last paragraph of Section 5.2 of [@RFC7515]
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

## Entropy of the Salt {#salt-entropy}

The security model that conceals the plaintext claims relies on the high entropy
random data of the salt as additional input to the hash function. The randomness
ensures that the same plaintext claim value does not produce the same digest value. It also
makes it infeasible to guess the preimage of the digest (thereby learning the
plaintext claim value) by enumerating the potential value
space for a claim into the hash function to search for a matching digest value.
It is therefore vitally important that unrevealed salts cannot be learned or guessed,
even if other salts have been revealed. As such, each salt MUST be created
in such a manner that it is cryptographically random, sufficiently long, and
has high enough entropy that it is infeasible to guess. A
new salt MUST be chosen for each claim independently of other salts.
See Randomness Requirements for Security [@RFC4086] for considerations
on generating random values.

The RECOMMENDED minimum length of the randomly-generated portion of the salt is 128 bits.

The Issuer MUST ensure that a new salt value is chosen for each claim,
including when the same claim name occurs at different places in the
structure of the SD-JWT. This can be seen in the example in (#example-complex-structured-sd-jwt),
where multiple claims with the name `type` appear, but each of them has
a different salt.

## Choice of a Hash Algorithm

To ensure privacy of claims that are selectively disclosable, but are not being disclosed in a given presentation,
the hash function MUST ensure that it is infeasible to calculate any portion of the three elements
(salt, claim name, claim value) from a particular digest. This implies the hash function MUST
be preimage resistant, but should also not allow an observer to infer any partial information about
the undisclosed content. In the terminology of cryptographic commitment schemes, the hash function
needs to be computationally hiding.

To ensure the integrity of selectively disclosable claims, the hash function MUST be second-preimage
resistant. That is, for any combination of salt, claim name and claim value, it is infeasible to find a different combination of salt,
claim name and claim value that result in the same digest.

The hash function SHOULD also be collision resistant. Although not essential to the anticipated uses of
SD-JWT, without collision resistance an Issuer may be able to find multiple disclosures that have the
same hash value. In which case, the signature over the SD-JWT would not then commit the Issuer to the contents of the
JWT. The collision resistance of the hash function used to generate digests SHOULD
match the collision resistance of the hash function used by the signature scheme. For example, use of
the ES512 signature algorithm would require a disclosure hash function with at least 256-bit collision
resistance, such as SHA-512.

Inclusion in the "Named Information Hash Algorithm" registry [@IANA.Hash.Algorithms]
alone does not indicate a hash algorithm's suitability for use in SD-JWT (it contains several
heavily truncated digests, such as `sha-256-32` and `sha-256-64`, which are unfit for security
applications).

Furthermore, the hash algorithms MD2, MD4, MD5, and SHA-1
revealed fundamental weaknesses and MUST NOT be used.

## Key Binding {#key_binding_security}

Key Binding aims to ensure that the presenter of an SD-JWT credential is actually the Holder of the credential.
An SD-JWT compatible with Key Binding contains a public key, or a reference to a public key, that corresponds to a private key possessed by the Holder.
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
decisions based on data that can be influenced by an attacker. For this reason, when deciding whether Key
Binding is required or not, Verifiers MUST NOT take into account
whether the Holder has provided an SD-JWT+KB or a bare SD-JWT, since otherwise an
attacker could strip the KB-JWT from an SD-JWT+KB and present the resulting SD-JWT.

Furthermore, Verifiers should be aware that Key Binding information may have been added to an SD-JWT in a format that they do not recognize and therefore may not be able to tell whether the SD-JWT supports Key Binding or not.

If a Verifier determines that Key Binding is required for a
particular use case and the Holder presents either a bare SD-JWT or an SD-JWT+KB with
an invalid Key Binding JWT, then the Verifier will reject the presentation
when following the verification steps described in (#verifier_verification).

## Concealing Claim Names

SD-JWT ensures that names of claims that are selectively disclosable are
always concealed unless the claim's value is disclosed. This prevents an attacker from learning the names of such
claims. However, the names of the claims that are permanently
disclosed are not hidden. This includes the keys of objects that themselves
are not concealed, but contain concealed claims. This limitation
needs to be taken into account by Issuers when creating the structure of
the SD-JWT.

## Selectively-Disclosable Validity Claims {#sd-validity-claims}

An Issuer MUST NOT allow any content to be selectively disclosable that is critical for evaluating the
SD-JWT's authenticity or validity.
The exact list of such content will depend on the application
and SHOULD be listed by any application-specific profiles of SD-JWT.
The following is a list of registered JWT claim names that SHOULD be considered as
security-critical:

* `iss` (Issuer)
* `aud` (Audience), although issuers MAY allow individual entries in the array to be selectively disclosable
* `exp` (Expiration Time)
* `nbf` (Not Before)
* `cnf` (Confirmation Key)

Issuers will typically include claims controlling the validity of the SD-JWT
in plaintext in the SD-JWT payload, but there is no guarantee they would do so. Therefore, Verifiers cannot
reliably depend on that and need to operate as though security-critical claims might be
selectively disclosable.

Verifiers therefore MUST ensure that all claims they deem necessary for checking
the validity of an SD-JWT in the given context are present (or disclosed, respectively) during
validation of the SD-JWT. This is implemented in the last
step of the verification defined in (#sd_jwt_verification).

The precise set of required validity claims will typically be defined by
operating environment rules, application-specific profile, or the credential format and MAY include claims other than
those listed herein.

## Distribution and Rotation of Issuer Signature Verification Key  {#issuer_signature_key_distribution}

This specification does not define how signature verification keys of
Issuers are distributed to Verifiers. However, it is RECOMMENDED that
Issuers publish their keys in a way that allows for efficient and secure
key rotation and revocation, for example, by publishing keys at a
predefined location using the JSON Web Key Set (JWKS) format [@RFC7517].
Verifiers need to ensure that they are not using expired or revoked keys
for signature verification using reasonable and appropriate means for the given
key-distribution method.

## Forwarding Credentials

Any entity in possession of an SD-JWT (including an SD-JWT extracted from an SD-JWT+KB) can forward it to any third party
that does not enforce Key Binding.
When doing so, that entity may remove Disclosures such that the receiver
learns only a subset of the claims contained in the original SD-JWT.

For example, a device manufacturer might produce an SD-JWT
containing information about upstream and downstream supply chain contributors.
Each supply chain party can verify only the claims that were selectively disclosed to them
by an upstream party, and they can choose to further reduce the disclosed claims
when presenting to a downstream party.

In some scenarios this behavior could be desirable,
but if it is not, Issuers need to support and Verifiers need to enforce Key Binding.

## Integrity of SD-JWTs and SD-JWT+KBs

With an SD-JWT, the Issuer-signed JWT is integrity-protected by the Issuer's
signature, and the values of the Disclosures are integrity-protected by the digests
included therein. The specific set of Disclosures, however,
is not integrity-protected; the SD-JWT can be modified by adding or
removing Disclosures and still be valid.

With an SD-JWT+KB, the set of selected Disclosures is integrity-protected.
The signature in the Key Binding JWT covers a
specific SD-JWT, with a specific Issuer-signed JWT and a specific set of
Disclosures.  Thus, the signature on the Key Binding JWT, in addition to proving
Key Binding, also assures the authenticity and integrity of the set of
Disclosures the Holder disclosed.  The set of Disclosures in an SD-JWT+KB is the set
that the Holder intended to send; no intermediate party has added, removed, or
modified the list of Disclosures.

## Explicit Typing {#explicit_typing}

[@!RFC8725, section 3.11] describes the use of explicit typing as one mechanism to prevent confusion attacks
(described in [@!RFC8725, section 2.8]) in which one kind of JWT is mistaken for another. SD-JWTs are also potentially
subject to such confusion attacks, so in the absence of other techniques, it is RECOMMENDED that application profiles of SD-JWT specify an explicit type
by including the `typ` header parameter when the SD-JWT is issued, and for Verifiers to check this value.

When explicit typing using the `typ` header is employed for an SD-JWT, it is RECOMMENDED that a media type name of the format
"application/example+sd-jwt" be used, where "example" is replaced by the identifier for the specific kind of SD-JWT.
The definition of `typ` in Section 4.1.9 of [@!RFC7515] recommends that the "application/" prefix be omitted, so
"example+sd-jwt" would be the value of the `typ` header parameter.

Use of the `cty` content type header parameter to indicate the content type of the SD-JWT payload can also be used to distinguish different types of JSON objects, or different kinds of JWT Claim Sets.

## Key Pair Generation and Lifecycle Management

Implementations of SD-JWT rely on asymmetric cryptographic keys and must therefore ensure that key pair generation,
handling, storage, and lifecycle management are performed securely.

While the specific mechanisms for secure key management are out of scope for this document, implementers
should follow established best practices, such as those outlined in NIST SP 800-57 Part 1 [@?NIST.SP.800-57pt1r5].
This includes:

* Secure Generation: Using cryptographically secure methods and random number generators.
* Secure Storage: Protecting private keys from unauthorized access.
* Lifecycle Management: Ensuring secure key rotation, revocation, and disposal as needed.

Appropriate key management is essential, as any compromise can lead to unauthorized disclosure or forgery of SD-JWTs.


# Privacy Considerations {#privacy_considerations}

## Unlinkability {#unlinkability}

Unlinkability is a property whereby adversaries are prevented from correlating
credential presentations of the same user beyond the user's consent.
Without unlinkability, an adversary might be able to learn more about the user than the user
intended to disclose, for example:

* Cooperating Verifiers might want to track users across services to build
  advertising profiles.
* Issuers might want to track where users present their credentials to enable
  surveillance.
* After a data breach at multiple Verifiers, publicly available information
  might allow linking identifiable information presented to Verifier A with
  originally anonymous information presented to Verifier B, therefore revealing
  the identities of users of Verifier B.

The following types of unlinkability are discussed below:

* Presentation Unlinkability: A Verifier should not be able to link two
  presentations of the same credential.
* Verifier/Verifier Unlinkability: The presentations made to two different
  Verifiers should not reveal that the same credential was presented (e.g., if the two
  Verifiers collude, or if they are forced by a third party to reveal the presentations
  made to them, or data leaks from one Verifier to the other).
* Issuer/Verifier Unlinkability (Honest Verifier): An Issuer of a credential
  should not be able to know that a user presented this credential unless
  the Verifier is sharing presentation data with the Issuer
  accidentally, deliberately, or because it is forced to do so.
* Issuer/Verifier Unlinkability (Careless/Colluding/Compromised/Coerced Verifier): An Issuer of a
  credential should under no circumstances be able to tell that a user presented this credential to
  a certain Verifier. In particular this includes cases when the Verifier accidentally or deliberately shares
  presentation data with the Issuer or is forced to do so.

In all cases, unlinkability is limited to cases where the disclosed claims do
not contain information that directly or indirectly identifies the user. For
example, when a taxpayer identification number is contained in the disclosed claims, the Issuer and
Verifier can easily link the user's transactions. However, when the user only
discloses a birthdate to one Verifier and a postal code to another Verifier, the two Verifiers should not be able to determine that they were interacting with the same user.

Issuer/Verifier unlinkability with a careless, colluding, compromised, or coerced Verifier cannot be
achieved in salted-hash based selective disclosure approaches, such as SD-JWT, as the
issued credential with the Issuer's signature is directly presented to the Verifier, who can forward it to
the Issuer. To reduce the risk of revealing the data later on, (#data_storage) defines
requirements to reduce the amount of data stored.

In considering Issuer/Verifier unlinkability, it is important to note the potential for an asymmetric power dynamic
between Issuers and Verifiers. This dynamic can compel an otherwise honest Verifier into collusion.
For example, a governmental Issuer might have the authority to mandate that a Verifier report back information
about the credentials presented to it. Legal requirements could further enforce this, explicitly undermining
Issuer/Verifier unlinkability. Similarly, a large service provider issuing credentials might implicitly pressure
Verifiers into collusion by incentivizing participation in their larger operating environment.
Deployers of SD-JWT must be aware of these potential power dynamics,
mitigate them as much as possible, and/or make the risks transparent to the user.

Contrary to that, Issuer/Verifier unlinkability with an honest Verifier can generally be achieved.
However, a callback from the Verifier to the Issuer, such as a revocation check, could potentially
disclose information about the credential's usage to the Issuer.
Where such callbacks are necessary, they need to be executed in a manner that
preserves privacy and does not disclose details about the credential to the Issuer
(the mechanism described in [@?I-D.ietf-oauth-status-list] is an example of an approach
with minimal information disclosure towards the Issuer). It is
important to note that the timing of such requests could potentially serve as a side-channel.

Verifier/Verifier unlinkability and presentation unlinkability can be achieved using batch issuance: A batch
of credentials based on the same claims is issued to the Holder instead of just
a single credential. The Holder can then use a different credential for each
Verifier or even for each session with a Verifier. New key binding keys and
salts MUST be used for each credential in the batch to ensure that the Verifiers
cannot link the credentials using these values. Likewise, claims carrying time
information, like `iat`, `exp`, and `nbf`, MUST either be randomized within a
time period considered appropriate (e.g., randomize `iat` within the last 24
hours and calculate `exp` accordingly) or rounded (e.g., rounded down to the
beginning of the day).

SD-JWT only conceals the value of claims that are not revealed.
It does not meet the security properties for anonymous credentials [@?CL01]. In
particular, colluding Verifiers and Issuers can know when they have seen the same
credential no matter what fields have been disclosed, even when none have been disclosed.
This behavior may not align with what users naturally anticipate or are guided to
expect from user interface interactions, potentially causing them to make decisions
they might not otherwise make. Workarounds such as batch issuance, as
described above, help with keeping
Verifiers from linking different presentations, but cannot work for Issuer/Verifier unlinkability.
This issue applies to all salted hash-based approaches,
including mDL/mDoc [@?ISO.18013-5] and SD-CWT [@?I-D.ietf-spice-sd-cwt].

## Storage of User Data {#data_storage}

Wherever user data is stored, it represents a potential
target for an attacker. This target can be of particularly
high value when the data is signed by a trusted authority like an
official national identity service. For example, in OpenID Connect [@?OpenID.Core],
signed ID Tokens can be stored by Relying Parties. In the case of
SD-JWT, Holders have to store SD-JWTs,
and Issuers and Verifiers may decide to do so as well.

Not surprisingly, a leak of such data risks revealing private data of users
to third parties. Signed user data, the authenticity of which
can be easily verified by third parties, further exacerbates the risk.
As discussed in (#key_binding_security), leaked
SD-JWTs may also allow attackers to impersonate Holders unless Key
Binding is enforced and the attacker does not have access to the
Holder's cryptographic keys.

Due to these risks, and the risks described in (#unlinkability), systems implementing SD-JWT SHOULD be designed to minimize
the amount of data that is stored. All involved parties SHOULD NOT store SD-JWTs
longer than strictly needed, including in log files.

After Issuance, Issuers SHOULD NOT store the Issuer-signed JWT or the respective
Disclosures.

Holders SHOULD store SD-JWTs only in
encrypted form, and, wherever possible, use hardware-backed encryption
in particular for the private Key Binding key. Decentralized storage
of data, e.g., on user devices, SHOULD be preferred for user
credentials over centralized storage. Expired SD-JWTs SHOULD be deleted
as soon as possible.

After Verification, Verifiers SHOULD NOT store the Issuer-signed JWT or the
respective Disclosures. It may be
sufficient to store the result of the verification and any user data that is
needed for the application.

Exceptions from the rules above can be made if there are strong requirements to do
so (e.g., functional requirements or legal audit requirements), secure storage can
be ensured, and the privacy impact has been assessed.


## Confidentiality during Transport

If the SD-JWT is transmitted over an insecure
channel during issuance or presentation, an adversary may be able to
intercept and read the user's personal data or correlate the information with previous uses of the same SD-JWT.

Usually, transport protocols for issuance and presentation of credentials
are designed to protect the confidentiality of the transmitted data, for
example, by requiring the use of TLS.

This specification therefore considers the confidentiality of the data to be
provided by the transport protocol and does not specify any encryption
mechanism.

Implementers MUST ensure that the transport protocol provides confidentiality
if the privacy of user data or correlation attacks by passive observers are a concern.

To encrypt the SD-JWT when transmitted over an insecure channel, implementers MAY use JSON Web Encryption (JWE) [@!RFC7516] by nesting the SD-JWT as the plaintext payload of a JWE.
Especially, when an SD-JWT is transmitted via a URL and information may be stored/cached in the browser or end up in web server logs, the SD-JWT SHOULD be encrypted using JWE.

## Decoy Digests {#decoy_digests_privacy}

The use of decoy digests is RECOMMENDED when the number of claims (or the existence of particular claims) can be a side-channel disclosing information about otherwise undisclosed claims. In particular, if a claim in an SD-JWT is present only if a certain condition is met (e.g., a membership number is only contained if the user is a member of a group), the Issuer SHOULD add decoy digests when the condition is not met.

Decoy digests increase the size of the SD-JWT. The number of decoy digests (or whether to use them at all) is a trade-off between the size of the SD-JWT and the privacy of the user's data.

## Issuer Identifier

An Issuer issuing only one type of SD-JWT might have privacy implications, because if the Holder has an SD-JWT issued by that Issuer, its type and claim names can be determined.

For example, if the National Cancer Institute only issued SD-JWTs with cancer registry information, it is possible to deduce that the Holder owning its SD-JWT is a cancer patient.

Moreover, the issuer identifier alone may reveal information about the user.

For example, when a military organization or a drug rehabilitation center issues a vaccine credential, verifiers can deduce that the holder is a military member or may have a substance use disorder.

To mitigate this issue, a group of issuers may elect to use a common Issuer identifier. A group signature scheme outside the scope of this specification may also be used, instead of an individual signature.

# Acknowledgements {#Acknowledgements}

We would like to thank
Alen Horvat,
Alex Hodder,
Anders Rundgren,
Arjan Geluk,
Chad Parry,
Christian Bormann,
Christian Paquin,
Dale Bowie,
David Bakker,
David Waite,
Dick Hardt,
Fabian Hauck,
Filip Skokan,
Giuseppe De Marco,
Jacob Ward,
Jeffrey Yasskin,
John Mattsson,
Joseph Heenan,
Justin Richer,
Kushal Das,
Martin Thomson,
Matthew Miller,
Michael Fraser,
Michael B. Jones,
Mike Prorock,
Nat Sakimura,
Neil Madden,
Oliver Terbu,
Orie Steele,
Paul Bastian,
Peter Altmann,
Pieter Kasselman,
Richard Barnes,
Rohan Mahy,
Ryosuke Abe,
Sami Rosendahl,
Shawn Emery,
Shawn Butterfield,
Simon Schulz,
Tobias Looker,
Takahiko Kawasaki,
Torsten Lodderstedt,
Vittorio Bertocci,
Watson Ladd, and
Yaron Sheffer
for their contributions (some of which were substantial) to this draft and to the initial set of implementations.

The work on this draft was started at OAuth Security Workshop 2022 in Trondheim, Norway.


# IANA Considerations {#iana_considerations}

## JSON Web Token Claims Registration

This specification requests registration of the following Claims in the
IANA "JSON Web Token Claims" registry [@IANA.JWT] established by [@!RFC7519].


*  Claim Name: `_sd`
*  Claim Description: Digests of Disclosures for object properties
*  Change Controller: IETF
*  Specification Document(s):  [[ (#embedding_object_properties) of this specification ]]

<br/>

*  Claim Name: `...`
*  Claim Description: Digest of the Disclosure for an array element
*  Change Controller: IETF
*  Specification Document(s):  [[ (#embedding_array_elements) of this specification ]]

<br/>

*  Claim Name: `_sd_alg`
*  Claim Description: Hash algorithm used to generate Disclosure digests and digest over presentation
*  Change Controller: IETF
*  Specification Document(s):  [[ (#hash_function_claim) of this specification ]]

<br/>

*  Claim Name: `sd_hash`
*  Claim Description: Digest of the SD-JWT to which the KB-JWT is tied
*  Change Controller: IETF
*  Specification Document(s):  [[ (#kb-jwt) of this specification ]]

## Media Type Registration

This section requests registration of the following media types [@RFC2046] in
the "Media Types" registry [@IANA.MediaTypes] in the manner described
in [@!RFC6838].

> Note: For the media type value used in the `typ` header in the Issuer-signed JWT
itself, see (#explicit_typing).

To indicate that the content is an SD-JWT:

* Type name: application
* Subtype name: sd-jwt
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: binary; application/sd-jwt values are a series of base64url-encoded values (some of which may be the empty string) separated by period ('.') and tilde ('~') characters.
* Security considerations: See the Security Considerations section of [[ this specification ]], [@!RFC7519], and [@!RFC8725].
* Interoperability considerations: n/a
* Published specification: [[ this specification ]]
* Applications that use this media type: Applications requiring selective disclosure of integrity protected content.
* Fragment identifier considerations: n/a
* Additional information:
   * Magic number(s): n/a
   * File extension(s): n/a
   * Macintosh file type code(s): n/a
* Person & email address to contact for further information: Daniel Fett, mail@danielfett.de
* Intended usage: COMMON
* Restrictions on usage: none
* Author: Daniel Fett, mail@danielfett.de
* Change Controller: IETF
* Provisional registration?  No

<br/>
To indicate that the content is a JWS JSON serialized SD-JWT:

* Type name: application
* Subtype name: sd-jwt+json
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: binary; application/sd-jwt+json values are represented as a JSON Object.
* Security considerations: See the Security Considerations section of [[ this specification ]], and [@!RFC7515].
* Interoperability considerations: n/a
* Published specification: [[ this specification ]]
* Applications that use this media type: Applications requiring selective disclosure of content protected by ETSI JAdES compliant signatures.
* Fragment identifier considerations: n/a
* Additional information:
    * Magic number(s): n/a
    * File extension(s): n/a
    * Macintosh file type code(s): n/a
* Person & email address to contact for further information: Daniel Fett, mail@danielfett.de
* Intended usage: COMMON
* Restrictions on usage: none
* Author: Daniel Fett, mail@danielfett.de
* Change Controller: IETF
* Provisional registration?  No

<br/>
To indicate that the content is a Key Binding JWT:

* Type name: application
* Subtype name: kb+jwt
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: binary; A Key Binding JWT is a JWT; JWT values are encoded as a series of base64url-encoded values separated by period ('.') characters.
* Security considerations: See the Security Considerations section of [[ this specification ]], [@!RFC7519], and [@!RFC8725].
* Interoperability considerations: n/a
* Published specification: [[ this specification ]]
* Applications that use this media type: Applications utilizing a JWT based proof of possession mechanism.
* Fragment identifier considerations: n/a
* Additional information:
   * Magic number(s): n/a
   * File extension(s): n/a
   * Macintosh file type code(s): n/a
* Person & email address to contact for further information: Daniel Fett, mail@danielfett.de
* Intended usage: COMMON
* Restrictions on usage: none
* Author: Daniel Fett, mail@danielfett.de
* Change Controller: IETF
* Provisional registration?  No

##  Structured Syntax Suffix Registration

This section requests registration of the "+sd-jwt" structured syntax suffix in
the "Structured Syntax Suffix" registry [@IANA.StructuredSuffix] in
the manner described in [@!RFC6838], which can be used to indicate that
the media type is encoded as an SD-JWT.

* Name: SD-JWT
* +suffix: +sd-jwt
* References: [[ this specification ]]
* Encoding considerations: binary; SD-JWT values are a series of base64url-encoded values (some of which may be the empty string) separated by period ('.') or tilde ('~') characters.
* Interoperability considerations: n/a
* Fragment identifier considerations: n/a
* Security considerations: See the Security Considerations section of [[ this specification ]], [@!RFC7519], and [@!RFC8725].
* Contact: Daniel Fett, mail@danielfett.de
* Author/Change controller: IETF


<reference anchor="OpenID.Core" target="https://openid.net/specs/openid-connect-core-1_0.html">
  <front>
    <title>OpenID Connect Core 1.0 incorporating errata set 2</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization abbrev="NAT.Consulting (was at NRI)">NAT.Consulting</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization abbrev="Yubico (was at Ping Identity)">Yubico</organization>
    </author>
    <author initials="M." surname="Jones" fullname="Mike Jones">
      <organization abbrev="Self-Issued Consulting (was at Microsoft)">Self-Issued Consulting</organization>
    </author>
    <author initials="B." surname="de Medeiros" fullname="Breno de Medeiros">
      <organization>Google</organization>
    </author>
    <author initials="C." surname="Mortimore" fullname="Chuck Mortimore">
      <organization abbrev="Disney (was at Salesforce)">Disney</organization>
    </author>
   <date day="15" month="Dec" year="2023"/>
  </front>
</reference>

<reference anchor="VC_DATA_v2.0" target="https://www.w3.org/TR/vc-data-model-2.0/">
  <front>
    <title>Verifiable Credentials Data Model 2.0 Candidate Recommendation Draft</title>
    <author fullname="Manu Sporny">
      <organization>Digital Bazaar</organization>
    </author>
    <author fullname="Ted Thiboeau Jr">
      <organization>OpenLink Software</organization>
    </author>
    <author fullname="Michael B. Jones">
      <organization>Invited Expert</organization>
    </author>
    <author fullname="Gabe Cohen">
      <organization>Block</organization>
    </author>
    <author fullname="Ivan Herman">
      <organization>W3C</organization>
    </author>
    <date day="09" month="Aug" year="2024"/>
  </front>
</reference>

<reference anchor="OIDC.IDA" target="https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html">
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
    <date day="24" month="Jul" year="2024"/>
  </front>
</reference>

<reference anchor="IANA.Hash.Algorithms" target="https://www.iana.org/assignments/named-information/named-information.xhtml">
  <front>
    <author fullname="IANA"></author>
    <title>Named Information Hash Algorithm</title>
  </front>
</reference>

<reference anchor="EUDIW.ARF" target="https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework">
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

<reference anchor="IANA.JWT" target="https://www.iana.org/assignments/jwt">
 <front>
  <title>JSON Web Token Claims</title>
  <author><organization>IANA</organization></author>
</front>
</reference>

<reference anchor="ISO.18013-5" target="https://www.iso.org/standard/69084.html">
<front>
  <title>ISO/IEC 18013-5:2021 Personal identification — ISO-compliant driving license — Part 5: Mobile driving license (mDL) application</title>
  <author>
    <organization> ISO/IEC JTC 1/SC 17 Cards and security devices for personal identification</organization>
  </author>
  <date year="2021"/>
</front>
</reference>

<reference anchor="CL01" target="https://eprint.iacr.org/2001/019.pdf">
  <front>
    <title>An Efficient System for Non-Transferable Anonymous Credentials with Optional Anonymity Revocation</title>
    <author initials="J." surname="Camenisch" fullname="Jan Camenisch">
      <organization>IBM Research</organization>
    </author>
    <author initials="A." surname="Lysyanskaya" fullname="Anna Lysyanskaya">
      <organization>MIT</organization>
    </author>
    <date year="2001" />
  </front>
  <seriesInfo name="Proceedings of the International Conference on the Theory and Application of Cryptographic Techniques (EUROCRYPT)" value="2001" />
</reference>

<reference anchor="NIST.SP.800-57pt1r5" target="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf">
  <front>
    <title>Recommendation for key management:part 1 - general</title>
    <author fullname="Elaine Barker" surname="Barker">
      <organization>Information Technology Laboratory</organization>
    </author>
    <author>
      <organization abbrev="NIST">National Institute of Standards and Technology</organization>
      <address>
        <postal>
          <country>US</country>
          <city>Gaithersburg</city>
        </postal>
      </address>
    </author>
    <date month="May" year="2020"/>
  </front>
  <seriesInfo name="NIST Special Publications (General)" value="800-57pt1r5"/>
  <seriesInfo name="DOI" value="10.6028/NIST.SP.800-57pt1r5"/>
</reference>

{backmatter}

# Additional Examples

The following examples are not normative and are provided for
illustrative purposes only. In particular, neither the structure of the claims
nor the selection of selectively disclosable claims is normative.

Line breaks have been added for readability.

## Simple Structured SD-JWT {#example-simple_structured}

In this example, in contrast to (#main-example), the Issuer decided to create a structured object for the `address` claim, allowing to separately disclose individual members of the claim.

The following data about the user comprises the input JWT Claims Set used by the Issuer:

<{{examples/simple_structured/user_claims.json}}

The Issuer also decided to add decoy digests to prevent the Verifier from deducing the true number of claims.

The following payload is used for the SD-JWT:

<{{examples/simple_structured/sd_jwt_payload.json}}

The digests in the SD-JWT payload reference the following Disclosures:

{{examples/simple_structured/disclosures.md}}

The following decoy digests are added:

{{examples/simple_structured/decoy_digests.md}}

The following is a presentation of the SD-JWT that discloses only `region`
and `country` of the `address` property:

<{{examples/simple_structured/sd_jwt_presentation.txt}}

After validation, the Verifier will have the following processed SD-JWT payload available for further handling:

<{{examples/simple_structured/verified_contents.json}}

## Complex Structured SD-JWT {#example-complex-structured-sd-jwt}

In this example, an SD-JWT with a complex object is represented. The data
structures defined in OpenID Connect for Identity Assurance [@OIDC.IDA] are used.

The Issuer is using the following user data as the input JWT Claims Set:

<{{examples/complex_ekyc/user_claims.json}}

The following payload is used for the SD-JWT:

<{{examples/complex_ekyc/sd_jwt_payload.json}}

The digests in the SD-JWT payload reference the following Disclosures:

{{examples/complex_ekyc/disclosures.md}}

The following is a presentation of the SD-JWT:

<{{examples/complex_ekyc/sd_jwt_presentation.txt}}

The Verifier will have this processed SD-JWT payload available after validation:

<{{examples/complex_ekyc/verified_contents.json}}

## SD-JWT-based Verifiable Credentials (SD-JWT VC)

This example shows how the artifacts defined in this specification could be
used in the context of SD-JWT-based Verifiable
Credentials (SD-JWT VC) [@I-D.ietf-oauth-sd-jwt-vc] to represent the concept of
a Person Identification Data (PID) as defined in the "PID Rulebook" in [@EUDIW.ARF]. This example uses fictional data of
a German citizen.

Key Binding is applied
using the Holder's public key passed in a `cnf` claim in the SD-JWT.

The following citizen data is the input JWT Claims Set:

<{{examples/arf-pid/user_claims.json}}

The following is the issued SD-JWT:

<{{examples/arf-pid/sd_jwt_issuance.txt}}

The following payload is used for the SD-JWT:

<{{examples/arf-pid/sd_jwt_payload.json}}

The digests in the SD-JWT payload reference the following Disclosures:

{{examples/arf-pid/disclosures.md}}

The following is an example of an SD-JWT+KB that discloses only nationality and the fact that the person is over 18 years old:

<{{examples/arf-pid/sd_jwt_presentation.txt}}

This is the payload of the corresponding Key Binding JWT:

<{{examples/arf-pid/kb_jwt_payload.json}}

After validation, the Verifier will have the following processed SD-JWT payload available for further handling:

<{{examples/arf-pid/verified_contents.json}}

## W3C Verifiable Credentials Data Model v2.0

This non-normative example illustrates how the artifacts defined in this specification
could be used to express a W3C Verifiable Credentials Data Model v2.0 [@VC_DATA_v2.0] payload.

Key Binding is applied
using the Holder's public key passed in a `cnf` claim in the SD-JWT.

The following is the input JWT Claims Set:

<{{examples/jsonld/user_claims.json}}

The following is the issued SD-JWT:

<{{examples/jsonld/sd_jwt_issuance.txt}}

The following payload is used for the SD-JWT:

<{{examples/jsonld/sd_jwt_payload.json}}

The digests in the SD-JWT payload reference the following Disclosures:

{{examples/jsonld/disclosures.md}}

This is an example of an SD-JWT+KB that discloses only `type`, `medicinalProductName`, `atcCode` of the vaccine, `type` of the `recipient`, `type`, `order` and `dateOfVaccination`:

<{{examples/jsonld/sd_jwt_presentation.txt}}

After the validation, the Verifier will have the following processed SD-JWT payload available for further handling:

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
approach in JWS and particularly useful when the content, like JSON, can have different representations but is semantically equivalent, thus avoiding canonicalization. Some further discussion of the considerations around this design decision follows.

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

However, a problem arises when computation over the data needs to be performed and verified, like signing or computing digests. Common signature schemes require the same byte string as input to the
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
specification, JSON is used and plaintext contents of each Disclosure are encoded using base64url-encoding
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

   -19

   * Attempt to improve some language around exactly what bytes get base64url encoded
   * Update the ABNF to something that is cleaner and more idiomatic
   * updates from AD's review of comments

   -18

   * Update PID example to align with the latest ARF and update the ARF reference
   * Editorial updates from SECDIR IETF LC review
   * Terminology improvements around the phrase "non-selectively disclosable claims" and "not disclosable"
   * Suggest against using extra claims/headers in the KB-JWT without a good reason

   -17

   * Acknowledgements updates

   -16

   * Updates following review of -15 by Hannes Tschofenig, document shepherd
   * Editorial updates to text introduced in -15
   * Changes based on feedback received after the end of the second working group last call

   -15

   * Additions and adjustments to privacy considerations
   * Address AD review comments resulting from evaluation of formal appeal
   * Clarify language around compromised/coerced verifiers

   -14

   * Address WGLC (part 2) comments
   * Note that the Hash Function Claim value is case-sensitive
   * Update the `typ` value in the SD-JWT VC example to `dc+sd-jwt` to align with anticipated changes in the SD-JWT VC draft.

   -13

   * WGLC (part 1) updates
   * Rewrote introduction
   * Added note on algorithm for Holder's verification of the SD-JWT

   -12

   * Clarify, add context, or otherwise improve the examples
   * Editorial and reference fixes
   * Better introduce the phrase processed SD-JWT payload in the end of (#sd_jwt_verification) on Verifying the SD-JWT
   * Moved considerations around unlinkability to the top of the Privacy Considerations section
   * Remove the brief discussion of publishing private key(s) to attempt to reduce the value of leaked or stolen data

   -11

   * Add a paragraph attempting to better frame the risks and difficulties around Issuer/Verifier
      unlinkability (i.e., a government issuer or huge service provider compelling collusion)
   * Tightened the exposition

   -10

   * Add a section clarifying recursive disclosures and their interdependencies
   * Editorial updates/fixes

   -09

   * Distinguished SD-JWT from SD-JWT+KB
   * Provide ABNF for the SD-JWT, SD-JWT+KB, and various constituent parts
   * New structure for JSON-serialized SD-JWTs/KB-JWTs to better align with JAdES.
   * Attempt to better explain how salt in the Disclosure makes guessing the preimage of the digest infeasible
   * Consolidate salt entropy and length security consideration subsections
   * Unnumbered most of the examples for improved clarity
   * More definitive language around the exclusive use of the `cnf` claim for enabling Key Binding

   -08

   * Make RFCs 0020 and 7515 normative references
   * Be a bit more prescriptive in suggesting RFC7800 cnf/jwk be used to convey the Key Binding key
   * Editorial changes aimed at improved clarity
   * Improve unlinkability considerations, mention that different KB keys must be used
   * Remove the explicit prohibition on HMAC
   * Remove mention of unspecified key binding methods and the Enveloping SD-JWTs section
   * Editorial updates aimed at more consistent treatment of a Disclosure vs the contents of a Disclosure
   * Update PID example
   * Be more explicit that the VCDM and SD-JWT VC examples are only illustrative and do not define anything

   -07

   * Reference RFC4086 in security considerations about salt entropy
   * Update change controller for the Structured Syntax Suffix registration from IESG to IETF per IANA suggestion
   * Strengthen security considerations around claims controlling the validity of the SD-JWT not being selectively disclosable
   * Expand/rework considerations on the choice of hash algorithm
   * Clarify validation around no duplicate digests in the payload (directly or recursively) and no unused disclosures at the end of processing
   * Better describe and illustrate the tilde separated format
   * Change claim name from `_sd_hash` to `sd_hash`


   -06

   * Added hash of Issuer-signed part and Disclosures in KB-JWT
   * Fix minor issues in some examples
   * Added IANA media type registration request for the JSON Serialization
   * More precise wording around storing artifacts with sensitive data
   * The claim name `_sd` or `...` must not be used in a disclosure.
   * Added JWT claims registration requests to IANA
   * Ensure claims that control validity are checked after decoding payload
   * Restructure sections around data formats and Example 1
   * Update JSON Serialization to remove the kb_jwt member and allow for the disclosures to be conveyed elsewhere
   * Expand the Enveloping SD-JWTs section to also discuss enveloping JSON serialized SD-JWTs

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
   * Aligned examples structure and used the term input JWT Claims Set
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


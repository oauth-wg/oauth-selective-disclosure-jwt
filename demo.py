import random
import re
import sys
from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256
from json import dumps
from textwrap import fill

from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from simplejson import loads
from secrets import compare_digest

# issuer
ISSUER = "https://example.com/issuer"

# Create the issuer's key in JWK format
ISSUER_KEY = JWK.generate(key_size=2048, kty="RSA")
ISSUER_PUBLIC_KEY = JWK.from_json(ISSUER_KEY.export_public())

# Create the holder's key in JWK format
HOLDER_KEY = JWK.generate(key_size=2048, kty="RSA")

# Define the claims
FULL_USER_CLAIMS = {
    "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
    "given_name": "John",
    "family_name": "Doe",
    "email": "johndoe@example.com",
    "phone_number": "+1-202-555-0101",
    "address": {
        "street_address": "123 Main St",
        "locality": "Anytown",
        "region": "Anystate",
        "country": "US",
    },
    "birthdate": "1940-01-01",
}

# The salts will be selected by the server, of course.
def generate_salt():
    return (
        urlsafe_b64encode(bytes(random.getrandbits(8) for _ in range(16)))
        .decode("ascii")
        .strip("=")
    )


NONCE = generate_salt()

#######################################################################

print("# Creating the SD-JWT")


def hash_raw(raw):
    # Calculate the SHA 256 hash and output it base64 encoded
    return urlsafe_b64encode(sha256(raw).digest()).decode("ascii").strip("=")


def hash_claim(salt, value, return_raw=False):
    raw = dumps([salt, value])
    if return_raw:
        return raw
    # Calculate the SHA 256 hash and output it base64 encoded
    return hash_raw(raw.encode("utf-8"))


print(f"User claims:\n```\n{dumps(FULL_USER_CLAIMS, indent=4)}\n```")


def create_sd_jwt_and_svc(user_claims, issuer, issuer_key):
    """
    Create the SD-JWT
    """

    salts = {name: generate_salt() for name in user_claims}

    # Create the JWS payload
    sd_jwt_payload = {
        "iss": issuer,
        "sub_jwk": issuer_key.export_public(as_dict=True),
        "iat": 1516239022,
        "exp": 1516247022,
        "sd_claims": {
            name: hash_claim(salts[name], value) for name, value in user_claims.items()
        },
    }

    # Sign the SD-JWT using the issuer's key
    sd_jwt = JWS(payload=dumps(sd_jwt_payload))
    sd_jwt.add_signature(issuer_key, alg="RS256", protected=dumps({"alg": "RS256"}))
    serialized_sd_jwt = sd_jwt.serialize(compact=True)

    # Create the SVC
    svc_payload = {
        "sd_claims": {
            name: hash_claim(salts[name], value, return_raw=True)
            for name, value in user_claims.items()
        },
        # "sub_jwk_private": issuer_key.export_private(as_dict=True),
    }
    serialized_svc = (
        urlsafe_b64encode(dumps(svc_payload, indent=4).encode("utf-8"))
        .decode("ascii")
        .strip("=")
    )

    # Return the JWS
    return sd_jwt_payload, serialized_sd_jwt, svc_payload, serialized_svc


sd_jwt_payload, serialized_sd_jwt, svc_payload, serialized_svc = create_sd_jwt_and_svc(
    FULL_USER_CLAIMS, ISSUER, ISSUER_KEY
)

print("Payload of the SD-JWT:\n```\n" + dumps(sd_jwt_payload, indent=4) + "\n```\n\n")

print("The serialized SD-JWT:\n```\n" + serialized_sd_jwt + "\n```\n\n")

print("Payload of the SD-JWT SVC:\n```\n" + dumps(svc_payload, indent=4) + "\n```\n\n")

print("The serialized SD-JWT SVC:\n```\n" + serialized_svc + "\n```\n\n")

combined_sd_jwt_svc = serialized_sd_jwt + "." + serialized_svc

#######################################################################

print("# Creating the SD-JWT-Release")

disclosed_claims = ["given_name", "family_name", "address"]


def create_release_jwt(nonce, aud, disclosed_claims, serialized_svc, holder_key):
    # Reconstruct hash raw values (salt+claim value) from serialized_svc

    hash_raw_values = loads(urlsafe_b64decode(serialized_svc + "=="))["sd_claims"]
    print(hash_raw_values)

    sd_jwt_release_payload = {
        "nonce": nonce,
        "aud": aud,
        "sd_claims": {name: hash_raw_values[name] for name in disclosed_claims},
    }

    # Sign the SD-JWT-Release using the holder's key
    sd_jwt_release = JWS(payload=dumps(sd_jwt_release_payload))
    sd_jwt_release.add_signature(
        holder_key, alg="RS256", protected=dumps({"alg": "RS256"})
    )
    serialized_sd_jwt_release = sd_jwt_release.serialize(compact=True)

    return sd_jwt_release_payload, serialized_sd_jwt_release


sd_jwt_release_payload, serialized_sd_jwt_release = create_release_jwt(
    NONCE, "https://example.com/verifier", disclosed_claims, serialized_svc, HOLDER_KEY
)

print(
    "Payload of the SD-JWT-Release:\n```\n"
    + dumps(sd_jwt_release_payload, indent=4)
    + "\n```\n\n"
)


print("The serialized SD-JWT-Release:\n```\n" + serialized_sd_jwt_release + "\n```\n\n")

#######################################################################

print("# Creating the Combined Presentation")
# Combine both documents!
combined_sd_jwt_sd_jwt_release = serialized_sd_jwt + "." + serialized_sd_jwt_release

print("Combined Presentation:\n```\n" + combined_sd_jwt_sd_jwt_release + "\n```\n\n")

#######################################################################

print("# Verification")

# input: combined_sd_jwt_sd_jwt_release, holder_key, issuer_key

list_of_required_claims = ["family_name", "address"]

check_holder_binding = True


def _verify_sd_jwt(sd_jwt, issuer_public_key, expected_issuer):
    parsed_input_sd_jwt = JWS()
    parsed_input_sd_jwt.deserialize(sd_jwt)
    parsed_input_sd_jwt.verify(issuer_public_key, alg="RS256")

    sd_jwt_payload = loads(parsed_input_sd_jwt.payload)
    if sd_jwt_payload["iss"] != expected_issuer:
        raise ValueError("Invalid issuer")

    # TODO: Check exp/nbf/iat

    if "sd_claims" not in sd_jwt_payload:
        raise ValueError("No selective disclosure claims in SD-JWT")

    return sd_jwt_payload["sd_claims"]


def _verify_sd_jwt_release(
    sd_jwt_release, holder_public_key=None, expected_aud=None, expected_nonce=None
):
    parsed_input_sd_jwt_release = JWS()
    parsed_input_sd_jwt_release.deserialize(sd_jwt_release)
    if holder_public_key:
        parsed_input_sd_jwt_release.verify(holder_public_key, alg="RS256")

    sd_jwt_release_payload = loads(parsed_input_sd_jwt_release.payload)

    if holder_public_key:
        if sd_jwt_release_payload["aud"] != expected_aud:
            raise ValueError("Invalid audience")
        if sd_jwt_release_payload["nonce"] != expected_nonce:
            raise ValueError("Invalid nonce")

    if "sd_claims" not in sd_jwt_release_payload:
        raise ValueError("No selective disclosure claims in SD-JWT-Release")

    return sd_jwt_release_payload["sd_claims"]


def verify(
    combined_presentation,
    required_claims,
    issuer_public_key,
    expected_issuer,
    holder_public_key=None,
    expected_aud=None,
    expected_nonce=None,
):
    if holder_public_key and (not expected_aud or not expected_nonce):
        raise ValueError(
            "When holder binding is to be checked, aud and nonce need to be provided."
        )

    parts = combined_presentation.split(".")
    if len(parts) != 6:
        raise ValueError("Invalid number of parts in the combined presentation")

    # Verify the SD-JWT
    input_sd_jwt = ".".join(parts[:3])
    sd_jwt_claims = _verify_sd_jwt(input_sd_jwt, issuer_public_key, expected_issuer)

    # Verify the SD-JWT-Release
    input_sd_jwt_release = ".".join(parts[3:])
    sd_jwt_release_claims = _verify_sd_jwt_release(
        input_sd_jwt_release, holder_public_key, expected_aud, expected_nonce
    )

    verified_claims = {}

    for claim_name in required_claims:
        if claim_name not in sd_jwt_claims:
            raise ValueError("Claim not found in SD-JWT: " + claim_name)

        if claim_name not in sd_jwt_release_claims:
            raise ValueError("Claim not found in SD-JWT-Release: " + claim_name)

        # the hash of the release claim value must match the claim value in the sd_jwt
        hashed_release_value = hash_raw(
            sd_jwt_release_claims[claim_name].encode("utf-8")
        )
        expected_hash = sd_jwt_claims[claim_name]
        if not compare_digest(hashed_release_value, expected_hash):
            raise ValueError(
                "Claim release value does not match the claim value in the SD-JWT"
            )

        decoded = loads(sd_jwt_release_claims[claim_name])
        if not isinstance(decoded, list):
            raise ValueError("Claim release value is not a list")

        if len(decoded) != 2:
            raise ValueError("Claim release value is not of length 2")

        verified_claims[claim_name] = decoded[1]

    return verified_claims


vc = verify(
    combined_sd_jwt_sd_jwt_release,
    list_of_required_claims,
    ISSUER_PUBLIC_KEY,
    ISSUER,
    HOLDER_KEY,
    "https://example.com/verifier",
    NONCE,
)

print("Verified claims: " + dumps(vc, indent=4))

#######################################################################
# Helper functions to replace the examples in the markdown file
#######################################################################


def replace_code_in_markdown_source(file_contents, placeholder_id, new_code):
    """
    the markdown contains code blocks that look like this:
    {#placeholder-id}
    ```
    some-code
    ```

    This function replaces the code block with the replacement
    """

    def replacement(match):
        return match.group(1) + new_code + "\n```"

    new_string, count = re.subn(
        r"({#" + placeholder_id + r"}\n```[a-z-_]*\n)(?:[\s\S]*?)\n```",
        replacement,
        file_contents,
        flags=re.MULTILINE,
    )
    if count == 0:
        raise ValueError(f"Could not find placeholder with id {placeholder_id}")

    return new_string


def replace_all_in_main(replacements):
    """
    Replaces all the placeholders in the main.md file
    """
    with open("main.md", "r") as f:
        file_contents = f.read()

    # create backup
    with open("main.md.bak", "w") as f:
        f.write(file_contents)

    for placeholder_id, new_code in replacements.items():
        file_contents = replace_code_in_markdown_source(
            file_contents, placeholder_id, new_code
        )

    with open("main.md", "w") as f:
        f.write(file_contents)


EXAMPLE_INDENT = 4
EXAMPLE_MAX_WIDTH = 70

if "--replace" in sys.argv:
    print("Replacing the placeholders in the main.md file")
    replacements = {
        "example-sd-jwt-claims": dumps(FULL_USER_CLAIMS, indent=EXAMPLE_INDENT),
        "example-sd-jwt-payload": dumps(sd_jwt_payload, indent=EXAMPLE_INDENT),
        "example-sd-jwt-encoded": fill(
            combined_sd_jwt_svc, width=EXAMPLE_MAX_WIDTH, break_on_hyphens=False
        ),
        "example-svc-payload": dumps(svc_payload, indent=EXAMPLE_INDENT),
        "example-combined-encoded": fill(
            combined_sd_jwt_sd_jwt_release,
            width=EXAMPLE_MAX_WIDTH,
            break_on_hyphens=False,
        ),
        "example-release-payload": dumps(sd_jwt_release_payload, indent=EXAMPLE_INDENT),
        "example-release-encoded": fill(
            serialized_sd_jwt_release, width=EXAMPLE_MAX_WIDTH, break_on_hyphens=False
        ),
        "example-release-combined": fill(
            combined_sd_jwt_sd_jwt_release,
            width=EXAMPLE_MAX_WIDTH,
            break_on_hyphens=False,
        ),
    }
    replace_all_in_main(replacements)

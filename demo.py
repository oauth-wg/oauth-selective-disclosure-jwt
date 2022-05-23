import random
import re
import sys
from base64 import urlsafe_b64encode
from hashlib import sha256
from json import dumps
from textwrap import fill

from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

# Create the issuer's key in JWK format
issuer_key = JWK.generate(key_size=2048, kty="RSA")

# Create the holder's key in JWK format
holder_key = JWK.generate(key_size=2048, kty="RSA")

# Define the claims
full_user_claims = {
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


salts = {name: generate_salt() for name in full_user_claims}

#######################################################################

print("# Creating the SD-JWT")


def hash_claim(salt, value, return_raw=False):
    raw = dumps([salt, value])
    if return_raw:
        return raw
    # Calculate the SHA 256 hash and output it base64 encoded
    return (
        urlsafe_b64encode(sha256(raw.encode("utf-8")).digest())
        .decode("ascii")
        .strip("=")
    )


sd_jwt_payload = {
    "iss": "https://example.com/issuer",
    "sub_jwk": issuer_key.export_public(as_dict=True),
    "iat": 1516239022,
    "exp": 1516247022,
    "sd_claims": {
        name: hash_claim(salts[name], value) for name, value in full_user_claims.items()
    },
}

print(f"User claims:\n```\n{dumps(full_user_claims, indent=4)}\n```")

print("Payload of the SD-JWT:\n```\n" + dumps(sd_jwt_payload, indent=4) + "\n```\n\n")

# Sign the SD-JWT using the issuer's key
sd_jwt = JWS(payload=dumps(sd_jwt_payload))
sd_jwt.add_signature(issuer_key, alg="RS256", protected=dumps({"alg": "RS256"}))
serialized_sd_jwt = sd_jwt.serialize(compact=True)
print("The serialized SD-JWT:\n```\n" + serialized_sd_jwt + "\n```\n\n")

svc_payload = {
    "sd_claims": {
        name: hash_claim(salts[name], value, return_raw=True)
        for name, value in full_user_claims.items()
    },
    #"sub_jwk_private": issuer_key.export_private(as_dict=True),
}
print("Payload of the SD-JWT SVC:\n```\n" + dumps(svc_payload, indent=4) + "\n```\n\n")

serialized_svc = urlsafe_b64encode(dumps(svc_payload, indent=4).encode("utf-8")).decode("ascii").strip("=")

print(
    "The serialized SD-JWT SVC:\n```\n"
    + serialized_svc
    + "\n```\n\n"
)

combined_sd_jwt_svc = serialized_sd_jwt + "." + serialized_svc

#######################################################################

print("# Creating the SD-JWT-Release")

disclosed_claims = ["family_name", "address"]

sd_jwt_release_payload = {
    "nonce": generate_salt(),
    "aud": "https://example.com/verifier",
    "sd_claims": {
        name: hash_claim(salts[name], full_user_claims[name], return_raw=True)
        for name in disclosed_claims
    },
}

print(
    "Payload of the SD-JWT-Release:\n```\n" + dumps(sd_jwt_release_payload, indent=4) + "\n```\n\n"
)


# Sign the SD-JWT-Release using the holder's key
sd_jwt_release = JWS(payload=dumps(sd_jwt_release_payload))
sd_jwt_release.add_signature(holder_key, alg="RS256", protected=dumps({"alg": "RS256"}))
serialized_sd_jwt_release = sd_jwt_release.serialize(compact=True)

print(
    "The serialized SD-JWT-Release:\n```\n"
    + serialized_sd_jwt_release
    + "\n```\n\n"
)

#######################################################################

print("# Creating the Combined Presentation")
# Combine both documents!
combined_sd_jwt_sd_jwt_release = serialized_sd_jwt_release + "." + sd_jwt_release.serialize(compact=True)

print("Combined Presentation:\n```\n" + combined_sd_jwt_sd_jwt_release + "\n```\n\n")


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

    new_string, count =  re.subn(
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
        "example-sd-jwt-claims": dumps(full_user_claims, indent=EXAMPLE_INDENT),
        "example-sd-jwt-payload": dumps(sd_jwt_payload, indent=EXAMPLE_INDENT),
        "example-sd-jwt-encoded": fill(combined_sd_jwt_svc, width=EXAMPLE_MAX_WIDTH, break_on_hyphens=False),
        "example-svc-payload": dumps(svc_payload, indent=EXAMPLE_INDENT),
        "example-combined-encoded": fill(combined_sd_jwt_sd_jwt_release, width=EXAMPLE_MAX_WIDTH, break_on_hyphens=False),
        "example-release-payload": dumps(sd_jwt_release_payload, indent=EXAMPLE_INDENT),
        "example-release-encoded": fill(serialized_sd_jwt_release, width=EXAMPLE_MAX_WIDTH, break_on_hyphens=False),
        "example-release-combined": fill(combined_sd_jwt_sd_jwt_release, width=EXAMPLE_MAX_WIDTH, break_on_hyphens=False),
    }
    replace_all_in_main(replacements)

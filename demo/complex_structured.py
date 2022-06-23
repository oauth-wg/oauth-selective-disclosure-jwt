import sys
from json import dumps
from textwrap import fill

from jwcrypto.jwk import JWK

from .lib import *

# issuer
ISSUER = "https://example.com/issuer"

# Create the issuer's key in JWK format
ISSUER_KEY = JWK.generate(key_size=2048, kty="RSA")
ISSUER_PUBLIC_KEY = JWK.from_json(ISSUER_KEY.export_public())

# Create the holder's key in JWK format
HOLDER_KEY = JWK.generate(key_size=2048, kty="RSA")

# Define the claims
FULL_USER_CLAIMS = {
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
                        "issuer": {"name": "Stadt Augsburg", "country": "DE"},
                        "number": "53554554",
                        "date_of_issuance": "2010-03-23",
                        "date_of_expiry": "2020-03-22",
                    },
                }
            ],
        },
        "claims": {
            "given_name": "Max",
            "family_name": "Meier",
            "birthdate": "1956-01-28",
            "place_of_birth": {"country": "DE", "locality": "Musterstadt"},
            "nationalities": ["DE"],
            "address": {
                "locality": "Maxstadt",
                "postal_code": "12344",
                "country": "DE",
                "street_address": "An der Weide 22",
            },
        },
    },
    "birth_middle_name": "Timotheus",
    "salutation": "Dr.",
    "msisdn": "49123456789",
}

CLAIMS_STRUCTURE = {
    "verified_claims": {
        "verification": {
            "evidence": [
                {
                    "document": {
                        "issuer": {},
                    }
                }
            ]
        },
        "claims": {
            "place_of_birth": {},
        },
    }
}

DISCLOSED_CLAIMS = {
    "verified_claims": {
        "verification": {
            "trust_framework": None,
            "time": None,
            "evidence": [{"type": None}],
        },
        "claims": {
            "given_name": None,
            "family_name": None,
            "birthdate": None,
            "place_of_birth": {"country": None},
        },
    },
}


NONCE = generate_salt()

#######################################################################

print("# Creating the SD-JWT")


print(f"User claims:\n{dumps(FULL_USER_CLAIMS, indent=4)}")


sd_jwt_payload, serialized_sd_jwt, svc_payload, serialized_svc = create_sd_jwt_and_svc(
    FULL_USER_CLAIMS, ISSUER, ISSUER_KEY, HOLDER_KEY, CLAIMS_STRUCTURE
)

print("Payload of the SD-JWT:\n" + dumps(sd_jwt_payload, indent=4) + "\n\n")

print("The serialized SD-JWT:\n" + serialized_sd_jwt + "\n\n")

print("Payload of the SD-JWT SVC:\n" + dumps(svc_payload, indent=4) + "\n\n")

print("The serialized SD-JWT SVC:\n" + serialized_svc + "\n\n")

combined_sd_jwt_svc = serialized_sd_jwt + "." + serialized_svc

#######################################################################

print("# Creating the SD-JWT-Release")


sd_jwt_release_payload, serialized_sd_jwt_release = create_release_jwt(
    NONCE, "https://example.com/verifier", DISCLOSED_CLAIMS, serialized_svc, HOLDER_KEY
)

print(
    "Payload of the SD-JWT-Release:\n"
    + dumps(sd_jwt_release_payload, indent=4)
    + "\n\n"
)


print("The serialized SD-JWT-Release:\n" + serialized_sd_jwt_release + "\n\n")

#######################################################################

print("# Creating the Combined Presentation")
# Combine both documents!
combined_sd_jwt_sd_jwt_release = serialized_sd_jwt + "." + serialized_sd_jwt_release

print("Combined Presentation:\n" + combined_sd_jwt_sd_jwt_release + "\n\n")

#######################################################################

print("# Verification")

# input: combined_sd_jwt_sd_jwt_release, holder_key, issuer_key

vc = verify(
    combined_sd_jwt_sd_jwt_release,
    ISSUER_PUBLIC_KEY,
    ISSUER,
    HOLDER_KEY,
    "https://example.com/verifier",
    NONCE,
)

print("Verified claims: " + dumps(vc, indent=4))

#######################################################################
# Replace the examples in the markdown file
#######################################################################


EXAMPLE_INDENT = 2
EXAMPLE_MAX_WIDTH = 70

if "--replace" in sys.argv:
    print("Replacing the placeholders in the main.md file")
    replacements = {
        "example-complex_structured-sd-jwt-claims": dumps(FULL_USER_CLAIMS, indent=EXAMPLE_INDENT),
        "example-complex_structured-sd-jwt-payload": dumps(sd_jwt_payload, indent=EXAMPLE_INDENT),
        "example-complex_structured-sd-jwt-encoded": fill(
            combined_sd_jwt_svc, width=EXAMPLE_MAX_WIDTH, break_on_hyphens=False
        ),
        "example-complex_structured-svc-payload": dumps(svc_payload, indent=EXAMPLE_INDENT),
        "example-complex_structured-combined-encoded": fill(
            combined_sd_jwt_sd_jwt_release,
            width=EXAMPLE_MAX_WIDTH,
            break_on_hyphens=False,
        ),
        "example-complex_structured-release-payload": dumps(sd_jwt_release_payload, indent=EXAMPLE_INDENT),
        "example-complex_structured-release-encoded": fill(
            serialized_sd_jwt_release, width=EXAMPLE_MAX_WIDTH, break_on_hyphens=False
        ),
        "example-complex_structured-release-combined": fill(
            combined_sd_jwt_sd_jwt_release,
            width=EXAMPLE_MAX_WIDTH,
            break_on_hyphens=False,
        ),
    }
    replace_all_in_main(replacements, ignore_missing_placeholders=True)

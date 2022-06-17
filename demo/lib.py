import random
import re
import sys
from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256
from json import dumps, loads
from secrets import compare_digest

from jwcrypto.jws import JWS
from jwcrypto.jwk import JWK

from .walk_by_structure import walk_by_structure

SD_CLAIMS_KEY = "_sd"

# For the purpose of generating static examples for the spec, this command line
# switch disables randomness. Using this in production is highly insecure!
if "--no-randomness" in sys.argv:
    random.seed(0)

    ISSUER_KEY = JWK.from_json(
        dumps(
            {
                "d": "JQ5-MZ5wuwb8KBYiJqDbtCG3H9daEK-ITOnxWP7k7jcI4lotkO3vmMuCw_XJQKShUV6TpeI7AT_je1SY_7-ram2oM1xJcm0zoOUOvK62l7006bUB3BfHmYXEdEtr_-bzA_mMwpQsEztT_V0BNIFwX-oXnO9LXSTrgFcUTUnS_Vyp-0noziWQN4sx5YlBTniRIhAyU1eYqUDpqza2hmKJEpEYUR73h3OLUEQJblEY4-WR989MK4ff_GcJ7y1dV8YraTmsoOKs2qmelMdfO_SgZ5SjKNtl38yvr8hkEJpXgbBJV1bjzu2IOysxmxtrOjxHRjDHQEV2MAoYObJki33rzQ",
                "dp": "gDE4XKCd_TbQLH_buP3UDpgCSi3TmdaTfmiNyJHxrNqBTehsMYhEUDN2t84NEJKF-QXWaRP1IHb3T5MvDNrXZUf8vHQFh6BXcOceF2dC_PvGIX3K1Nwnb8T9u1VkwaN95h_hMoCk7E8mKw37cX4eeoRqtLsxBSFODbIhi4b9Yq0",
                "dq": "c26RA1V_1rX8sfrMMkCDADbb7tD55h8obuX2FMs2LhBs4T9vzwsm8dKZ1cl0VYui04hc-x6tAMwYFrz4Y0cGBcHQHgOL1ame_pQos1tCbOChBeczXVLlcKhwsvFCNjkM4jV05o8PHZ9Jk8dFbGJ_1RLTgaGLktFQgfkas8VjwKs",
                "e": "AQAB",
                "key_size": 2048,
                "kty": "RSA",
                "n": "6GwTTwcjVyOtKtuGf7ft5PAU0GiDtnD4DGcmtVrFQHVhtx05-DJigfmR-3Tetw-Od5su4TNZYzjh3tQ6Bj1HRdOfGmX9E9YbPw4goKg_d0kM4oZMUd64tmlAUFtX0NYaYnRkjQtok2CJBUq22wucK93JV11T38PYDATqbK9UFqMM3vu07XXlaQGXP1vh4iX04w4dU4d2xTACXho_wKKcV85yvIGrO1eGwwnSilTiqQbak31_VnHGNVVZEk4dnVO7eOc6MVZa-qPkVj77GaILO53TMq69Vp1faJoGFHjha_Ue5D8zfpiAEx2AsAeotIwNk2QT0UZkeZoK23Q-s4p1dQ",
                "p": "8_vXPiy3OtAeACYgNm6iIo5c1Cbwuh3tJ0T6lMcGEo7Rcro0nwNFISvPnFp_1Wl8I1ts6FTMsKyoTneveDrptlWSRRZNrFS_GyAQpG6GPUfqNh9n4T5J3mYw6-fLPM0hL0_EbDNiEXyL53ecMfi2xlg2T2opuZFeToogqipDudc",
                "q": "8953MqqJ7v-bc5rPQuRjqbHIxZJdEF-VsSz1lVbVEqnxV0XEUnM8yZqsXUe07V-5OEzJBqgrgLCcOeh5Jfs1MZI9tegRCwdw3uiqECAAVMtsM9xCwBY0mPu-oqOwaKsVOj2Slr1Gq-s67FdjGeMq6udjPWHgQ5QeOy78pgHtWZM",
                "qi": "FghQIPGfbjWmdwl5szDRPq1_NcGWSt9Eswu5o-JJq-jWUgTljqxufteg96k7pmBXMAQjGKn_lY41AojokVB4KWTJrPHF6z6oAm90kMLuFi80IbXzdb6TnsYHue_Y3Tbs4GtYP7YU9x2zrghsaUcDNJ7yH13h9F7GyiDkpySgcaM",
            }
        )
    )
    HOLDER_KEY = JWK.from_json(
        dumps(
            {
                "d": "kJSUdxpBVUHSSe0HfJfeO3q-iDgjXlS9zEZmgifbUPtjcT8recXwmwwRTZzhb9avNy8tyL8i1dJooAeMnudECz4u5zRY6VIXnSkO2cSPhZ-fyXPpC1BAnzf8RSn8rGu_auRrfyq3dfYw6dLt7dzA-hsUANzD63x8Tt4v9eiwsp65BlR1pvf0BIV3WMGLtgx0hTUQBUxIx0hgDG439a0gLY0T86m9LEMCcVXONNTWbScQf5KsHLWQgbjCeUc_4szy4RwsaFnF40uut_fdZyM_O1pOsfYJLa8fmN3FC72l4UdJvtFXWuH-20ywTEOKISF7CRx5BsifOnyEMTeAVEE9wQ",
                "dp": "kqCTyxU7gJa3gY4tn9OABui7por98yRlQUl7HYo63nPYPhCK3zMFcEOL8xjYot1cYYCGxE5yFxqkbX9fmbWEsRmx_BsgRPdraZ5DhvCES3BYstJAVctS-2LikGMK7veV7r6tEoKPvmKrkOKH90_-0GVvdG0GJn7Ccqz9OTWa1sE",
                "dq": "DYqOZnhR_1GZhNaMyVdAOcLt3Sw20TL90pEPSbYLGtcBLqZkyo9wNtMguYd_YFXHojF_iNwQW9IdYE7hVgA87tLEgM8S-1zQFVI2jGkBbqHisncQ4NdbEdIXxc3YHyCQmurPPW_EjKhyRKzHoalkJoUUSWF0S34MXoiFHIEae-s",
                "e": "AQAB",
                "key_size": 2048,
                "kty": "RSA",
                "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x65659kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjtth8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mTz10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wqf_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSGuxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw",
                "p": "0AZrdzBIpxDQggVh0x4GYBmNDuC8Ut_qOAKNLbpJLaWHFmeMjQRnXM8nxZfmhzAQ10XAS6n7TyFqK-PrhfmKWZ0g34UVfeXd4-D-gqegIDZ3TNwNCOBLOpwdDrHeB06ZdJ1o2OI1XLTO12PQN6PRUVKKF0dFdXV7NAM8YpJkxmE",
                "q": "zM_2m4uE2ldfNMOJmCMRm2S2NpiMOYi3Pp6Q6c4QtpF1up0Bak0Whox4F6VN6ydJjgolXFITufUU4XhT8p9WvDdCrY5u3NWbGMXMC426JPHXBKdHqQvAf3LFcbWNjrjowBktkPyDbB5sL3H8ey-q6tzGqLirZGZSKFiZ6J3OUFM",
                "qi": "O7leKcjIonKzTlI2EcShf4Vdlw-AvlQqAHmpGttHP0Vr--R4RteORtdXGUZC92GNaiHmkDLwak8ENfewKUP9xMyE_Psc5N090P_y9yKaIQnqN5QYe7quisqYtD64xP-568JaQCCqUtrVFT62jFhl0cVQ8Fy2oqdaKBufjLv-ssc",
            }
        )
    )
    print("WARNING: Using fixed randomness for demo purposes")
else:
    ISSUER_KEY = JWK.generate(key_size=2048, kty="RSA")
    HOLDER_KEY = JWK.generate(key_size=2048, kty="RSA")


ISSUER_PUBLIC_KEY = JWK.from_json(ISSUER_KEY.export_public())


# The salts will be selected by the server, of course.
def generate_salt():
    return (
        urlsafe_b64encode(bytes(random.getrandbits(8) for _ in range(16)))
        .decode("ascii")
        .strip("=")
    )


def hash_raw(raw):
    # Calculate the SHA 256 hash and output it base64 encoded
    return urlsafe_b64encode(sha256(raw).digest()).decode("ascii").strip("=")


def hash_claim(salt, value, return_raw=False):
    raw = dumps([salt, value])
    if return_raw:
        return raw
    # Calculate the SHA 256 hash and output it base64 encoded
    return hash_raw(raw.encode("utf-8"))


def create_sd_jwt_and_svc(user_claims, issuer, issuer_key, holder_key, claim_structure={}):
    """
    Create the SD-JWT
    """

    salts = walk_by_structure(
        claim_structure, user_claims, lambda _, __, ___=None: generate_salt()
    )

    def _create_sd_claim_entry(_, value, salt):
        return hash_claim(salt, value)

    # Create the JWS payload
    sd_jwt_payload = {
        "iss": issuer,
        "sub_jwk": holder_key.export_public(as_dict=True),
        "iat": 1516239022,
        "exp": 1516247022,
        SD_CLAIMS_KEY: walk_by_structure(salts, user_claims, _create_sd_claim_entry),
    }

    # Sign the SD-JWT using the issuer's key
    sd_jwt = JWS(payload=dumps(sd_jwt_payload))
    sd_jwt.add_signature(issuer_key, alg="RS256", protected=dumps({"alg": "RS256"}))
    serialized_sd_jwt = sd_jwt.serialize(compact=True)

    def _create_svc_entry(_, value, salt):
        return hash_claim(salt, value, return_raw=True)

    # Create the SVC
    svc_payload = {
        SD_CLAIMS_KEY: walk_by_structure(salts, user_claims, _create_svc_entry),
        # "sub_jwk_private": issuer_key.export_private(as_dict=True),
    }
    serialized_svc = (
        urlsafe_b64encode(dumps(svc_payload, indent=4).encode("utf-8"))
        .decode("ascii")
        .strip("=")
    )

    # Return the JWS
    return sd_jwt_payload, serialized_sd_jwt, svc_payload, serialized_svc


def create_release_jwt(nonce, aud, disclosed_claims, serialized_svc, holder_key):
    # Reconstruct hash raw values (salt+claim value) from serialized_svc

    hash_raw_values = loads(urlsafe_b64decode(serialized_svc + "=="))[SD_CLAIMS_KEY]

    sd_jwt_release_payload = {
        "nonce": nonce,
        "aud": aud,
        SD_CLAIMS_KEY: walk_by_structure(
            hash_raw_values, disclosed_claims, lambda _, __, raw: raw
        ),
    }

    # Sign the SD-JWT-Release using the holder's key
    sd_jwt_release = JWS(payload=dumps(sd_jwt_release_payload))
    sd_jwt_release.add_signature(
        holder_key, alg="RS256", protected=dumps({"alg": "RS256"})
    )
    serialized_sd_jwt_release = sd_jwt_release.serialize(compact=True)

    return sd_jwt_release_payload, serialized_sd_jwt_release


def _verify_sd_jwt(sd_jwt, issuer_public_key, expected_issuer):
    parsed_input_sd_jwt = JWS()
    parsed_input_sd_jwt.deserialize(sd_jwt)
    parsed_input_sd_jwt.verify(issuer_public_key, alg="RS256")

    sd_jwt_payload = loads(parsed_input_sd_jwt.payload)
    if sd_jwt_payload["iss"] != expected_issuer:
        raise ValueError("Invalid issuer")

    # TODO: Check exp/nbf/iat

    if SD_CLAIMS_KEY not in sd_jwt_payload:
        raise ValueError("No selective disclosure claims in SD-JWT")

    holder_public_key_payload = None
    if "sub_jwk" in sd_jwt_payload:
        holder_public_key_payload = sd_jwt_payload["sub_jwk"]

    return sd_jwt_payload[SD_CLAIMS_KEY], holder_public_key_payload


def _verify_sd_jwt_release(
    sd_jwt_release, holder_public_key=None, expected_aud=None, expected_nonce=None, holder_public_key_payload = None
):
    parsed_input_sd_jwt_release = JWS()
    parsed_input_sd_jwt_release.deserialize(sd_jwt_release)
    if holder_public_key and holder_public_key_payload:
        pubkey = JWK.from_json(dumps(holder_public_key_payload))
        # Because of weird bug of failed != between two public keys
        if not holder_public_key == pubkey:
            raise ValueError("sub_jwk is not matching with HOLDER Public Key.")
    if holder_public_key:
        parsed_input_sd_jwt_release.verify(holder_public_key, alg="RS256")

    sd_jwt_release_payload = loads(parsed_input_sd_jwt_release.payload)

    if holder_public_key:
        if sd_jwt_release_payload["aud"] != expected_aud:
            raise ValueError("Invalid audience")
        if sd_jwt_release_payload["nonce"] != expected_nonce:
            raise ValueError("Invalid nonce")

    if SD_CLAIMS_KEY not in sd_jwt_release_payload:
        raise ValueError("No selective disclosure claims in SD-JWT-Release")

    return sd_jwt_release_payload[SD_CLAIMS_KEY]


def _check_claim(claim_name, released_value, sd_jwt_claim_value):
    # the hash of the release claim value must match the claim value in the sd_jwt
    hashed_release_value = hash_raw(released_value.encode("utf-8"))
    if not compare_digest(hashed_release_value, sd_jwt_claim_value):
        raise ValueError(
            "Claim release value does not match the claim value in the SD-JWT"
        )

    decoded = loads(released_value)
    if not isinstance(decoded, list):
        raise ValueError("Claim release value is not a list")

    if len(decoded) != 2:
        raise ValueError("Claim release value is not of length 2")

    return decoded[1]


def verify(
    combined_presentation,
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
    sd_jwt_claims, holder_public_key_payload = _verify_sd_jwt(input_sd_jwt, issuer_public_key, expected_issuer)

    # Verify the SD-JWT-Release
    input_sd_jwt_release = ".".join(parts[3:])
    sd_jwt_release_claims = _verify_sd_jwt_release(
        input_sd_jwt_release, holder_public_key, expected_aud, expected_nonce, holder_public_key_payload
    )

    return walk_by_structure(sd_jwt_claims, sd_jwt_release_claims, _check_claim)


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


def replace_all_in_main(replacements, ignore_missing_placeholders=False):
    """
    Replaces all the placeholders in the main.md file
    """
    with open("main.md", "r") as f:
        file_contents = f.read()

    # create backup
    with open("main.md.bak", "w") as f:
        f.write(file_contents)

    for placeholder_id, new_code in replacements.items():
        try:
            file_contents = replace_code_in_markdown_source(
                file_contents, placeholder_id, new_code
            )
        except ValueError:
            if not ignore_missing_placeholders:
                raise
            else:
                print(f"Could not find placeholder with id {placeholder_id}")

    with open("main.md", "w") as f:
        f.write(file_contents)

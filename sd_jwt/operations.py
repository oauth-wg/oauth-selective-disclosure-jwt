import datetime
import logging
import random
from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256
from json import dumps, loads
from secrets import compare_digest
from typing import Union

from jwcrypto.jws import JWS
from jwcrypto.jwk import JWK

from sd_jwt.utils import pad_urlsafe_b64
from sd_jwt.walk import by_structure as walk_by_structure
from sd_jwt import DEFAULT_SIGNING_ALG, SD_CLAIMS_KEY, SD_DIGESTS_KEY, HASH_ALG_KEY

DEFAULT_EXP_MINS = 15
# TODO: adopt a dynamic module/package loader, defs could be as string -> "fn": "hashlib.sha256"
HASH_ALG = {"name": "sha-256", "fn": sha256}

SD_JWT_HEADER = None # "sd+jwt"
# WiP: https://github.com/oauthstuff/draft-selective-disclosure-jwt/issues/60
SD_JWT_R_HEADER = None  # "sd+jwt-r"

logger = logging.getLogger("sd_jwt")


# The salts will be selected by the server, of course.
def generate_salt():
    return (
        urlsafe_b64encode(bytes(random.getrandbits(8) for _ in range(16)))
        .decode("ascii")
        .strip("=")
    )


def hash_raw(raw):
    # Calculate the SHA 256 hash and output it base64 encoded
    return urlsafe_b64encode(HASH_ALG["fn"](raw).digest()).decode("ascii").strip("=")


def hash_claim(salt, value, return_raw=False):
    # raw = f"{salt}{value}"
    raw = dumps([salt, value])
    if return_raw:
        return raw
        # return [salt, value]
    # Calculate the SHA 256 hash and output it base64 encoded
    return hash_raw(raw.encode())


def _create_sd_claim_entry(key, value: str, salt: str) -> str:
    """
    returns the hashed and salted value string
    key arg is not used here, it's just for compliances to other calls
    """
    return hash_claim(salt, value)


def _create_svc_entry(key, value: str, salt: str) -> str:
    """
    returns a string representation of a list
       [hashed and salted value string, value string]
    key arg is not used here, it's just for compliances to other calls
    """
    return hash_claim(salt, value, return_raw=True)


def create_sd_jwt_and_svc(
    user_claims: dict,
    issuer: str,
    issuer_key,
    holder_key,
    claim_structure: dict = {},
    iat: Union[int, None] = None,
    exp: Union[int, None] = None,
    sign_alg=None,
):
    """
    Create the SD-JWT
    """
    # something like: {'sub': 'zyZQuxk2AUv5_Z_RAMxh9Q', 'given_name': 'EpCuoArhQK6MjmO6D-Bi6w' ...
    salts = walk_by_structure(
        claim_structure, user_claims, lambda _, __, ___=None: generate_salt()
    )

    _iat = iat or int(datetime.datetime.utcnow().timestamp())
    _exp = exp or _iat + (DEFAULT_EXP_MINS * 60)
    _alg = sign_alg or DEFAULT_SIGNING_ALG

    # Create the JWS payload
    sd_jwt_payload = {
        "iss": issuer,
        "sub_jwk": holder_key.export_public(as_dict=True),
        "iat": _iat,
        "exp": _exp,
        HASH_ALG_KEY: HASH_ALG["name"],
        SD_DIGESTS_KEY: walk_by_structure(salts, user_claims, _create_sd_claim_entry),
    }

    # Sign the SD-JWT using the issuer's key
    sd_jwt = JWS(payload=dumps(sd_jwt_payload))
    _headers = {"alg": _alg, "kid": issuer_key.thumbprint()}
    if SD_JWT_HEADER:
        _headers["typ"] = SD_JWT_HEADER
    sd_jwt.add_signature(
        issuer_key,
        alg=_alg,
        protected=dumps(_headers),
    )
    serialized_sd_jwt = sd_jwt.serialize(compact=True)
    # Create the SVC
    svc_payload = {
        SD_CLAIMS_KEY: walk_by_structure(salts, user_claims, _create_svc_entry),
        # "sub_jwk_private": issuer_key.export_private(as_dict=True),
    }
    serialized_svc = (
        urlsafe_b64encode(dumps(svc_payload).encode()).decode("ascii").strip("=")
    )

    # Return the JWS
    return sd_jwt_payload, serialized_sd_jwt, svc_payload, serialized_svc


def create_release_jwt(
    nonce: str,
    aud: str,
    disclosed_claims: dict,
    serialized_svc: dict,
    holder_key: dict,
    sign_alg: str = None,
):
    # Reconstruct hash raw values (salt+claim value) from serialized_svc
    hash_raw_values = loads(urlsafe_b64decode(pad_urlsafe_b64(serialized_svc)))[
        SD_CLAIMS_KEY
    ]

    _alg = sign_alg or DEFAULT_SIGNING_ALG
    sd_jwt_r_struct = walk_by_structure(
        hash_raw_values, disclosed_claims, lambda _, __, raw: raw
    )
    sd_jwt_release_payload = {
        "nonce": nonce,
        "aud": aud,
        SD_CLAIMS_KEY: sd_jwt_r_struct,
    }

    # Sign the SD-JWT-Release using the holder's key
    sd_jwt_release = JWS(payload=dumps(sd_jwt_release_payload))

    _data = {"alg": _alg, "kid": holder_key.thumbprint()}
    if SD_JWT_R_HEADER:
        _data["typ"] = SD_JWT_R_HEADER

    sd_jwt_release.add_signature(
        holder_key,
        alg=_alg,
        protected=dumps(_data),
    )
    serialized_sd_jwt_release = sd_jwt_release.serialize(compact=True)
    return sd_jwt_release_payload, serialized_sd_jwt_release


def _verify_sd_jwt(
    sd_jwt: str, issuer_public_key: dict, expected_issuer: str, sign_alg: str = None
):
    parsed_input_sd_jwt = JWS()
    parsed_input_sd_jwt.deserialize(sd_jwt)
    parsed_input_sd_jwt.verify(issuer_public_key, alg=sign_alg)

    sd_jwt_payload = loads(parsed_input_sd_jwt.payload)
    if sd_jwt_payload["iss"] != expected_issuer:
        raise ValueError("Invalid issuer")

    # TODO: Check exp/nbf/iat
    if HASH_ALG_KEY not in sd_jwt_payload:
        raise ValueError("Missing hash algorithm")

    if sd_jwt_payload[HASH_ALG_KEY] != HASH_ALG["name"]:
        raise ValueError("Invalid hash algorithm")

    if SD_DIGESTS_KEY not in sd_jwt_payload:
        raise ValueError("No selective disclosure claims in SD-JWT")

    holder_public_key_payload = None
    if "sub_jwk" in sd_jwt_payload:
        holder_public_key_payload = sd_jwt_payload["sub_jwk"]

    return sd_jwt_payload[SD_DIGESTS_KEY], holder_public_key_payload


def _verify_sd_jwt_release(
    sd_jwt_release: Union[dict, str],  # the release could be signed by the holder
    holder_public_key: Union[dict, None] = None,
    expected_aud: Union[str, None] = None,
    expected_nonce: Union[str, None] = None,
    holder_public_key_payload: Union[dict, None] = None,
    sign_alg: Union[str, None] = None,
):
    _alg = sign_alg or DEFAULT_SIGNING_ALG
    parsed_input_sd_jwt_release = JWS()
    parsed_input_sd_jwt_release.deserialize(sd_jwt_release)
    if holder_public_key and holder_public_key_payload:
        pubkey = JWK.from_json(dumps(holder_public_key_payload))
        # TODO: adopt an OrderedDict here
        # Because of weird bug of failed != between two public keys
        if not holder_public_key == pubkey:
            raise ValueError("sub_jwk is not matching with HOLDER Public Key.")
    if holder_public_key:
        parsed_input_sd_jwt_release.verify(holder_public_key, alg=_alg)

    sd_jwt_release_payload = loads(parsed_input_sd_jwt_release.payload)

    if holder_public_key:
        if sd_jwt_release_payload["aud"] != expected_aud:
            raise ValueError("Invalid audience")
        if sd_jwt_release_payload["nonce"] != expected_nonce:
            raise ValueError("Invalid nonce")

    if SD_CLAIMS_KEY not in sd_jwt_release_payload:
        raise ValueError("No selective disclosure claims in SD-JWT-Release")

    return sd_jwt_release_payload[SD_CLAIMS_KEY]


def _check_claim(claim_name: str, released_value: str, sd_jwt_claim_value: str):
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
    combined_presentation: str,
    issuer_public_key: dict,
    expected_issuer: str,
    holder_public_key: Union[dict, None] = None,
    expected_aud: Union[str, None] = None,
    expected_nonce: Union[str, None] = None,
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
    sd_jwt_claims, holder_public_key_payload = _verify_sd_jwt(
        input_sd_jwt, issuer_public_key, expected_issuer
    )

    # Verify the SD-JWT-Release
    input_sd_jwt_release = ".".join(parts[3:])
    sd_jwt_release_claims = _verify_sd_jwt_release(
        input_sd_jwt_release,
        holder_public_key,
        expected_aud,
        expected_nonce,
        holder_public_key_payload,
    )

    return walk_by_structure(sd_jwt_claims, sd_jwt_release_claims, _check_claim)

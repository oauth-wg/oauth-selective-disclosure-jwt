import datetime

from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256
from json import dumps, loads
from secrets import compare_digest
from typing import Dict, List, Optional, Tuple, Union

from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

from sd_jwt import DEFAULT_SIGNING_ALG, HASH_ALG_KEY, SD_CLAIMS_KEY, SD_DIGESTS_KEY
from sd_jwt.utils import generate_salt, pad_urlsafe_b64, merge
from sd_jwt.walk import by_structure as walk_by_structure


class SDJWT:
    SD_JWT_HEADER = None  # "sd+jwt"
    # WiP: https://github.com/oauthstuff/draft-selective-disclosure-jwt/issues/60
    SD_JWT_R_HEADER = None  # "sd+jwt-r"
    DEFAULT_EXP_MINS = 15
    # TODO: adopt a dynamic module/package loader, defs could be as string -> "fn": "hashlib.sha256"
    HASH_ALG = {"name": "sha-256", "fn": sha256}

    HIDDEN_CLAIM_NAME_PREFIX = ""

    SD_KEY_SALT = "s"
    SD_KEY_VALUE = "v"
    SD_KEY_CLAIM_NAME = "n"

    # Issuer produces:
    salts_and_blinded_claim_names: Dict
    sd_jwt_payload: Dict
    sd_jwt: JWS
    serialized_sd_jwt: str
    svc_payload: Dict
    serialized_svc: str
    combined_sd_jwt_svc: str

    # Holder produces:
    sd_jwt_release_payload: Dict
    sd_jwt_release: JWS
    serialized_sd_jwt_release: str
    combined_presentation: str

    def __init__(
        self,
        user_claims: Dict,
        further_claims: Dict,
        issuer: str,
        issuer_key,
        holder_key,
        claims_structure: Optional[Dict] = None,
        blinded_claim_names: Optional[List] = None,
        iat: Optional[int] = None,
        exp: Optional[int] = None,
        sign_alg=None,
    ):
        self._user_claims = user_claims
        self._further_claims = further_claims
        self._issuer = issuer
        self._issuer_key = issuer_key
        self._holder_key = holder_key
        self._claims_structure = claims_structure or {}
        self._blinded_claim_names = blinded_claim_names or []
        self._iat = iat or int(datetime.datetime.utcnow().timestamp())
        self._exp = exp or self._iat + (self.DEFAULT_EXP_MINS * 60)
        self._sign_alg = sign_alg or DEFAULT_SIGNING_ALG

        self._create_salts_and_blinded_claim_names()
        self._assemble_sd_jwt_payload()
        self._create_signed_jwt()
        self._create_svc()
        self._create_combined()

    def _create_salts_and_blinded_claim_names(self):
        """
        This function generates a structure that follows the claims structure, but for
        each entry contains a tuple: the salt value plus a random string that can become
        the blinded claim name.
        """

        # something like: {'sub': ('zyZQuxk2AUv5_Z_RAMxh9Q', 'EpCuoArhQK6MjmO6D-Bi6w'), 'given_name': ('EpCuoArhQK6MjmO6D-Bi6w', 'ArhQK6MjmO6D-Bi6wud62k'). ...
        self.salts_and_blinded_claim_names = walk_by_structure(
            self._claims_structure,
            self._user_claims,
            lambda key, __, ___=None: (key, (generate_salt(), generate_salt())),
        )

    def _assemble_sd_jwt_payload(self):
        # Create the JWS payload
        self.sd_jwt_payload = {
            "iss": self._issuer,
            "cnf": self._holder_key.export_public(as_dict=True),
            "iat": self._iat,
            "exp": self._exp,
            HASH_ALG_KEY: self.HASH_ALG["name"],
            SD_DIGESTS_KEY: walk_by_structure(
                self.salts_and_blinded_claim_names,
                self._user_claims,
                self._create_sd_claim_entry,
            ),
        }
        self.sd_jwt_payload.update(self._further_claims)

    def _hash_raw(self, raw):
        # Calculate the SHA 256 hash and output it base64 encoded
        return (
            urlsafe_b64encode(self.HASH_ALG["fn"](raw).digest())
            .decode("ascii")
            .strip("=")
        )

    def _hash_claim(
        self, key, value, salt_and_blinded_claim_name, return_raw=False
    ) -> Tuple[str, str]:
        salt, blinded_claim_name = salt_and_blinded_claim_name
        if key in self._blinded_claim_names:
            raw = dumps(
                {
                    self.SD_KEY_SALT: salt,
                    self.SD_KEY_VALUE: value,
                    self.SD_KEY_CLAIM_NAME: key,
                }
            )
            output_key = self.HIDDEN_CLAIM_NAME_PREFIX + blinded_claim_name
        else:
            raw = dumps({self.SD_KEY_SALT: salt, self.SD_KEY_VALUE: value})
            output_key = key

        if return_raw:
            return (output_key, raw)
        # Calculate the SHA 256 hash and output it base64 encoded
        return (output_key, self._hash_raw(raw.encode()))

    def _create_sd_claim_entry(
        self, key, value: str, salt_and_blinded_claim_name: str
    ) -> Tuple[str, str]:
        """
        returns the hashed and salted value string
        key arg is not used here, it's just for compliance to other calls
        """
        return self._hash_claim(key, value, salt_and_blinded_claim_name)

    def _create_signed_jwt(self):
        """
        Create the SD-JWT
        """

        # Sign the SD-JWT using the issuer's key
        self.sd_jwt = JWS(payload=dumps(self.sd_jwt_payload))
        _headers = {"alg": self._sign_alg, "kid": self._issuer_key.thumbprint()}
        if self.SD_JWT_HEADER:
            _headers["typ"] = self.SD_JWT_HEADER
        self.sd_jwt.add_signature(
            self._issuer_key,
            alg=self._sign_alg,
            protected=dumps(_headers),
        )
        self.serialized_sd_jwt = self.sd_jwt.serialize(compact=True)

    def _create_svc(self):
        # Create the SVC
        self.svc_payload = {
            SD_CLAIMS_KEY: walk_by_structure(
                self.salts_and_blinded_claim_names,
                self._user_claims,
                self._create_svc_entry,
            ),
            # "cnf_private": issuer_key.export_private(as_dict=True),
        }
        self.serialized_svc = (
            urlsafe_b64encode(dumps(self.svc_payload).encode())
            .decode("ascii")
            .strip("=")
        )

    def _create_svc_entry(
        self, key, value: str, salt_and_blinded_claim_name: str
    ) -> Tuple[str, str]:
        """
        returns a string representation of a list
        [hashed and salted value string, value string]
        key arg is not used here, it's just for compliances to other calls
        """
        return self._hash_claim(
            key, value, salt_and_blinded_claim_name, return_raw=True
        )

    def _create_combined(self):
        self.combined_sd_jwt_svc = self.serialized_sd_jwt + "." + self.serialized_svc

    #### Holder Operations ####

    @classmethod
    def from_combined_sd_jwt_svc(cls, combined):
        sdjwt = cls.__new__(cls)
        sdjwt._parse_combined_sd_jwt_svc(combined)
        return sdjwt

    def _parse_combined_sd_jwt_svc(self, combined):

        parts = combined.split(".")
        if len(parts) != 4:
            raise ValueError("Invalid number of parts in the combined presentation")

        self.serialized_sd_jwt = ".".join(parts[:3])
        self.serialized_svc = parts[3]

        # Reconstruct hash raw values (salt+claim value) from serialized_svc
        self._input_hash_raw_values = loads(
            urlsafe_b64decode(pad_urlsafe_b64(self.serialized_svc))
        )[SD_CLAIMS_KEY]

        # TODO: Check that input_sd_jwt and input_svc match

    def create_sd_jwt_release(
        self, nonce, aud, disclosed_claims, holder_key, sign_alg: Optional[str] = None
    ):
        _alg = sign_alg or DEFAULT_SIGNING_ALG

        def find_claim_by_blinded_name(structure, key):
            if key in structure:
                return key
            for key_in_structure, value_in_structure in structure.items():
                if not key_in_structure.startswith(self.HIDDEN_CLAIM_NAME_PREFIX):
                    continue
                if not isinstance(value_in_structure, str):
                    continue
                parsed = loads(value_in_structure)
                if parsed.get(self.SD_KEY_CLAIM_NAME, None) == key:
                    return key_in_structure
            raise KeyError()

        sd_jwt_r_struct = walk_by_structure(
            self._input_hash_raw_values,
            disclosed_claims,
            lambda key, __, raw="???": (key, raw),
            find_claim_by_blinded_name,
        )

        self.sd_jwt_release_payload = {
            "nonce": nonce,
            "aud": aud,
            SD_CLAIMS_KEY: sd_jwt_r_struct,
        }

        # Sign the SD-JWT-Release using the holder's key
        self.sd_jwt_release = JWS(payload=dumps(self.sd_jwt_release_payload))

        _data = {"alg": _alg, "kid": holder_key.thumbprint()}
        if self.SD_JWT_R_HEADER:
            _data["typ"] = self.SD_JWT_R_HEADER

        self.sd_jwt_release.add_signature(
            holder_key,
            alg=_alg,
            protected=dumps(_data),
        )
        self.serialized_sd_jwt_release = self.sd_jwt_release.serialize(compact=True)

        self.combined_presentation = (
            self.serialized_sd_jwt + "." + self.serialized_sd_jwt_release
        )

    #### Verifier Operations ####

    @classmethod
    def from_combined_presentation(cls, combined_presentation):
        sdjwt = cls.__new__(cls)
        sdjwt._parse_combined_presentation(combined_presentation)
        return sdjwt

    def _parse_combined_presentation(self, combined_presentation):
        parts = combined_presentation.split(".")
        if len(parts) != 6:
            raise ValueError("Invalid number of parts in the combined presentation")

        # Extract the parts
        self._unverified_input_sd_jwt = ".".join(parts[:3])
        self._unverified_input_sd_jwt_release = ".".join(parts[3:])

    def verify(
        self,
        issuer_public_key: dict,
        expected_issuer: str,
        holder_public_key: Union[dict, None] = None,
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
        return_merged=False,
    ):

        if holder_public_key and (not expected_aud or not expected_nonce):
            raise ValueError(
                "When holder binding is to be checked, aud and nonce need to be provided."
            )

        sd_jwt_claims, holder_public_key_payload = self._verify_sd_jwt(
            self._unverified_input_sd_jwt, issuer_public_key, expected_issuer
        )

        sd_jwt_sd_claims = sd_jwt_claims[SD_DIGESTS_KEY]

        # Verify the SD-JWT-Release
        sd_jwt_release_claims = self._verify_sd_jwt_release(
            self._unverified_input_sd_jwt_release,
            holder_public_key,
            expected_aud,
            expected_nonce,
            holder_public_key_payload,
        )

        _wbs = walk_by_structure(
            sd_jwt_sd_claims, sd_jwt_release_claims, self._check_claim
        )
        if not return_merged:
            return _wbs
        else:
            del sd_jwt_claims[SD_DIGESTS_KEY]
            del sd_jwt_claims[HASH_ALG_KEY]
            return merge(_wbs, sd_jwt_claims)

    def _verify_sd_jwt(
        self,
        sd_jwt: str,
        issuer_public_key: dict,
        expected_issuer: str,
        sign_alg: str = None,
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

        if sd_jwt_payload[HASH_ALG_KEY] != SDJWT.HASH_ALG["name"]:
            raise ValueError("Invalid hash algorithm")

        if SD_DIGESTS_KEY not in sd_jwt_payload:
            raise ValueError("No selective disclosure claims in SD-JWT")

        holder_public_key_payload = None
        if "cnf" in sd_jwt_payload:
            holder_public_key_payload = sd_jwt_payload["cnf"]

        return sd_jwt_payload, holder_public_key_payload

    def _verify_sd_jwt_release(
        self,
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
                raise ValueError("cnf is not matching with HOLDER Public Key.")
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

    def _check_claim(
        self, claim_name: str, released_value: str, sd_jwt_claim_value: str
    ):
        # the hash of the release claim value must match the claim value in the sd_jwt
        hashed_release_value = self._hash_raw(released_value.encode("utf-8"))
        if not compare_digest(hashed_release_value, sd_jwt_claim_value):
            raise ValueError(
                "Claim release value does not match the claim value in the SD-JWT"
            )

        decoded = loads(released_value)
        if not isinstance(decoded, dict):
            raise ValueError("Claim release value is not a dictionary")

        output_claim_name = decoded.get(self.SD_KEY_CLAIM_NAME, claim_name)
        return (output_claim_name, decoded[self.SD_KEY_VALUE])

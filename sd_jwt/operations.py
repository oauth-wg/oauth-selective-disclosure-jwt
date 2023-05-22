import random
import secrets
from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256
from json import dumps, loads
from time import time
from typing import Dict, List, Optional, Tuple, Union, Callable

from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

from sd_jwt import DEFAULT_SIGNING_ALG, DIGEST_ALG_KEY, SD_DIGESTS_KEY


class SDKey(str):
    pass


class SDJWTHasSDClaimException(Exception):
    """Exception raised when input data contains the special _sd claim reserved for SD-JWT internal data."""

    def __init__(self, error_location: any):
        super().__init__(
            f"Input data contains the special claim '{SD_DIGESTS_KEY}' reserved for SD-JWT internal data. Location: {error_location!r}"
        )


class SDJWTCommon:
    SD_JWT_HEADER = None  # "sd+jwt"
    # WiP: https://github.com/oauthstuff/draft-selective-disclosure-jwt/issues/60
    SD_JWT_R_HEADER = "hb+jwt"  # "sd+jwt-r"
    # TODO: adopt a dynamic module/package loader, defs could be as string -> "fn": "hashlib.sha256"
    HASH_ALG = {"name": "sha-256", "fn": sha256}

    COMBINED_FORMAT_SEPARATOR = "~"

    unsafe_randomness = False

    def _b64hash(self, raw):
        # Calculate the SHA 256 hash and output it base64 encoded
        return self._base64url_encode(self.HASH_ALG["fn"](raw).digest())

    def _combine(self, *parts):
        return self.COMBINED_FORMAT_SEPARATOR.join(parts)

    def _split(self, combined):
        return combined.split(self.COMBINED_FORMAT_SEPARATOR)

    def _base64url_encode(self, data: bytes) -> str:
        return urlsafe_b64encode(data).decode("ascii").strip("=")

    def _base64url_decode(self, b64data: str) -> bytes:
        padded = f"{b64data}{'=' * divmod(len(b64data),4)[1]}"
        return urlsafe_b64decode(padded)

    def _generate_salt(self):
        if self.unsafe_randomness:
            # This is not cryptographically secure, but it is deterministic
            # and allows for repeatable output for the generation of the examples.
            print(
                "WARNING: Using unsafe randomness - output is not suitable for production use!"
            )
            return self._base64url_encode(
                bytes(random.getrandbits(8) for _ in range(16))
            )
        else:
            return self._base64url_encode(secrets.token_bytes(16))

    def _create_hash_mappings(self, disclosurses_list: List):
        # Mapping from hash of disclosure to the decoded disclosure
        self._hash_to_decoded_disclosure = {}

        # Mapping from hash of disclosure to the raw disclosure
        self._hash_to_disclosure = {}

        for disclosure in disclosurses_list:
            decoded_disclosure = loads(
                self._base64url_decode(disclosure).decode("utf-8")
            )
            hash = self._b64hash(disclosure.encode("ascii"))
            if hash in self._hash_to_decoded_disclosure:
                raise ValueError(
                    f"Duplicate disclosure hash {hash} for disclosure {decoded_disclosure}"
                )

            self._hash_to_decoded_disclosure[hash] = decoded_disclosure
            self._hash_to_disclosure[hash] = disclosure

    def _check_for_sd_claim(self, the_object):
        # Recursively check for the presence of the _sd claim, also
        # works for arrays and nested objects.
        if isinstance(the_object, dict):
            for key, value in the_object.items():
                if key == SD_DIGESTS_KEY:
                    raise SDJWTHasSDClaimException(the_object)
                else:
                    self._check_for_sd_claim(value)
        elif isinstance(the_object, list):
            for item in the_object:
                self._check_for_sd_claim(item)
        else:
            return


class SDJWTIssuer(SDJWTCommon):
    DECOY_MIN_ELEMENTS = 2
    DECOY_MAX_ELEMENTS = 5

    sd_jwt_payload: Dict
    sd_jwt: JWS
    serialized_sd_jwt: str

    ii_disclosures = []
    combined_sd_jwt_iid: str

    _debug_ii_disclosures_contents = []

    decoy_digests = []

    def __init__(
        self,
        user_claims: Dict,
        issuer_key,
        holder_key=None,
        sign_alg=None,
        add_decoy_claims: bool = False,
    ):
        self._user_claims = user_claims
        self._issuer_key = issuer_key
        self._holder_key = holder_key
        self._sign_alg = sign_alg or DEFAULT_SIGNING_ALG
        self._add_decoy_claims = add_decoy_claims

        self._check_for_sd_claim(self._user_claims)
        self._assemble_sd_jwt_payload()
        self._create_signed_jwt()
        self._create_combined()

    def _assemble_sd_jwt_payload(self):
        # Create the JWS payload
        self.sd_jwt_payload = self._create_sd_claims(self._user_claims)
        self.sd_jwt_payload.update(
            {
                DIGEST_ALG_KEY: self.HASH_ALG["name"],
            }
        )
        if self._holder_key:
            self.sd_jwt_payload["cnf"] = {
                "jwk": self._holder_key.export_public(as_dict=True)
            }

    def _hash_claim(self, key, value) -> Tuple[str, str]:
        json = dumps([self._generate_salt(), key, value]).encode("utf-8")
        self._debug_ii_disclosures_contents.append(json.decode("utf-8"))

        raw_b64 = self._base64url_encode(json)
        hash = self._b64hash(raw_b64.encode("ascii"))

        return (hash, raw_b64)

    def _create_sd_claim_entry(self, key, value: any) -> str:
        hash, raw_b64 = self._hash_claim(key, value)
        self.ii_disclosures.append(raw_b64)
        return hash

    def _create_decoy_claim_entry(self) -> str:
        digest = self._b64hash(self._generate_salt().encode("ascii"))
        self.decoy_digests.append(digest)
        return digest

    def _create_sd_claims(self, user_claims):
        # This function can be called recursively.
        #
        # If the user claims are a list, apply this function
        # to each item in the list. The first element in non_sd_claims
        # (which is assumed to be a list as well) is used as the
        # structure for each item in the list.
        if type(user_claims) is list:
            return [self._create_sd_claims(claim) for claim in user_claims]

        # If the user claims are a dictionary, apply this function
        # to each key/value pair in the dictionary. The structure
        # for each key/value pair is found in the non_sd_claims
        # dictionary. If the key is not found in the non_sd_claims
        # dictionary, then the value is assumed to be a claims that
        # should be selectively disclosable.
        elif type(user_claims) is dict:
            sd_claims = {SD_DIGESTS_KEY: []}
            for key, value in user_claims.items():
                subtree_from_here = self._create_sd_claims(value)
                if isinstance(key, SDKey):
                    # Assemble all hash digests in the disclosures list.
                    sd_claims[SD_DIGESTS_KEY].append(
                        self._create_sd_claim_entry(key, subtree_from_here)
                    )
                else:
                    sd_claims[key] = subtree_from_here

            # Add decoy claims if requested
            if self._add_decoy_claims:
                for _ in range(
                    random.randint(self.DECOY_MIN_ELEMENTS, self.DECOY_MAX_ELEMENTS)
                ):
                    sd_claims[SD_DIGESTS_KEY].append(self._create_decoy_claim_entry())

            # Delete the SD_DIGESTS_KEY if it is empty
            if len(sd_claims[SD_DIGESTS_KEY]) == 0:
                del sd_claims[SD_DIGESTS_KEY]
            else:
                # Sort the hash digests otherwise
                sd_claims[SD_DIGESTS_KEY].sort()

            return sd_claims

        # For other types, assume that the value can be disclosed.
        else:
            return user_claims

    def _create_signed_jwt(self):
        """
        Create the SD-JWT
        """

        # Sign the SD-JWT using the issuer's key
        self.sd_jwt = JWS(payload=dumps(self.sd_jwt_payload))
        _headers = {"alg": self._sign_alg}
        if self.SD_JWT_HEADER:
            _headers["typ"] = self.SD_JWT_HEADER
        self.sd_jwt.add_signature(
            self._issuer_key,
            alg=self._sign_alg,
            protected=dumps(_headers),
        )
        self.serialized_sd_jwt = self.sd_jwt.serialize(compact=True)

    def _create_combined(self):
        self.combined_sd_jwt_iid = self._combine(
            self.serialized_sd_jwt, *self.ii_disclosures
        )


class SDJWTHolder(SDJWTCommon):
    hs_disclosures: List
    holder_binding_jwt_payload: Dict
    holder_binding_jwt: JWS
    serialized_holder_binding_jwt: str = ""
    combined_presentation: str

    _ii_disclosures: List
    _hash_to_decoded_disclosure: Dict
    _hash_to_disclosure: Dict

    def __init__(self, combined_sd_jwt_iid: str):
        self._parse_combined_sd_jwt_iid(combined_sd_jwt_iid)
        self._create_hash_mappings(self._ii_disclosures)
        self._extract_payload_unverified()

    def _parse_combined_sd_jwt_iid(self, combined):
        self.serialized_sd_jwt, *self._ii_disclosures = self._split(combined)

    def _extract_payload_unverified(self):
        # TODO: This holder does not verify the SD-JWT yet - this
        # is not strictly needed, but it would be nice to have.

        # Extract only the body from SD-JWT without verifying the signature
        _, jwt_body, _ = self.serialized_sd_jwt.split(".")
        self.sd_jwt_payload = loads(self._base64url_decode(jwt_body))

    def create_presentation(
        self, claims_to_disclose, nonce=None, aud=None, holder_key=None, sign_alg=None
    ):
        # Select the disclosures
        self.hs_disclosures = []
        self._select_disclosures(self.sd_jwt_payload, claims_to_disclose)

        # Optional: Create a holder binding JWT
        if nonce and aud and holder_key:
            self._create_holder_binding_jwt(nonce, aud, holder_key, sign_alg)

        # Create the combined presentation
        # Note: If the holder binding JWT is not created, then the
        # last element is empty, matching the spec.
        self.combined_presentation = self._combine(
            self.serialized_sd_jwt,
            *self.hs_disclosures,
            self.serialized_holder_binding_jwt,
        )

    def _select_disclosures(self, sd_jwt_claims, claims_to_disclose):
        # Recursively process the claims in sd_jwt_claims. In each
        # object found therein, look at the SD_DIGESTS_KEY. If it
        # contains hash digests for claims that should be disclosed,
        # then add the corresponding disclosures to the claims_to_disclose.

        if type(sd_jwt_claims) is list:
            if type(claims_to_disclose) is not list or len(claims_to_disclose) < 1:
                reference = {}
            else:
                reference = claims_to_disclose[0]
            return [
                self._select_disclosures(claim, reference) for claim in sd_jwt_claims
            ]

        elif type(sd_jwt_claims) is dict:
            for key, value in sd_jwt_claims.items():
                if key == SD_DIGESTS_KEY:
                    for digest in value:
                        if digest not in self._hash_to_decoded_disclosure:
                            # fake digest
                            continue
                        decoded = self._hash_to_decoded_disclosure[digest]
                        _, key, value = decoded

                        try:
                            if key in claims_to_disclose:
                                self.hs_disclosures.append(
                                    self._hash_to_disclosure[digest]
                                )
                        except TypeError:
                            # claims_to_disclose is not a dict
                            raise TypeError(
                                f"claims_to_disclose does not contain a dict where a dict was expected (found {claims_to_disclose} instead)\n"
                                f"Check claims_to_disclose for key: {key}, value: {value}"
                            ) from None

                        self._select_disclosures(value, claims_to_disclose.get(key, {}))
                else:
                    self._select_disclosures(value, claims_to_disclose.get(key, {}))

        else:
            pass

    def _create_holder_binding_jwt(
        self, nonce, aud, holder_key, sign_alg: Optional[str] = None
    ):
        _alg = sign_alg or DEFAULT_SIGNING_ALG

        self.holder_binding_jwt_payload = {
            "nonce": nonce,
            "aud": aud,
            "iat": int(time()),
        }

        # Sign the SD-JWT-Release using the holder's key
        self.holder_binding_jwt = JWS(payload=dumps(self.holder_binding_jwt_payload))

        _data = {"alg": _alg}
        if self.SD_JWT_R_HEADER:
            _data["typ"] = self.SD_JWT_R_HEADER

        self.holder_binding_jwt.add_signature(
            holder_key,
            alg=_alg,
            protected=dumps(_data),
        )
        self.serialized_holder_binding_jwt = self.holder_binding_jwt.serialize(
            compact=True
        )


class SDJWTVerifier(SDJWTCommon):
    _hs_disclosures: List
    _hash_to_decoded_disclosure: Dict
    _hash_to_disclosure: Dict

    def __init__(
        self,
        combined_presentation: str,
        cb_get_issuer_key: Callable[[str], str],
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
    ):
        self._parse_combined_presentation(combined_presentation)
        self._create_hash_mappings(self._hs_disclosures)
        self._verify_sd_jwt(cb_get_issuer_key)

        # expected aud and nonce either need to be both set or both None
        if expected_aud or expected_nonce:
            if not (expected_aud and expected_nonce):
                raise ValueError(
                    "Either both expected_aud and expected_nonce must be set or both must be None"
                )

            # Verify the SD-JWT-Release
            self._verify_holder_binding_jwt(
                expected_aud,
                expected_nonce,
            )

    def get_verified_payload(self):
        return self._extract_sd_claims()

    def _parse_combined_presentation(self, combined):
        (
            self._unverified_input_sd_jwt,
            *self._hs_disclosures,
            self._unverified_input_holder_binding_jwt,
        ) = self._split(combined)

    def _extract_issuer_unverified_from_sd_jwt(self):
        # Extracts only the issuer from the raw SD-JWT without verifying the signature
        _, jwt_body, _ = self._unverified_input_sd_jwt.split(".")
        return loads(self._base64url_decode(jwt_body))["iss"]

    def _verify_sd_jwt(
        self,
        cb_get_issuer_key,
        sign_alg: str = None,
    ):
        parsed_input_sd_jwt = JWS()
        parsed_input_sd_jwt.deserialize(self._unverified_input_sd_jwt)
        unverified_payload_issuer = self._extract_issuer_unverified_from_sd_jwt()
        issuer_public_key = cb_get_issuer_key(unverified_payload_issuer)
        parsed_input_sd_jwt.verify(issuer_public_key, alg=sign_alg)

        self._sd_jwt_payload = loads(parsed_input_sd_jwt.payload.decode("utf-8"))
        # TODO: Check exp/nbf/iat

        self._holder_public_key_payload = self._sd_jwt_payload.get("cnf", None)

    def _verify_holder_binding_jwt(
        self,
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
        sign_alg: Union[str, None] = None,
    ):
        _alg = sign_alg or DEFAULT_SIGNING_ALG
        parsed_input_holder_binding_jwt = JWS()
        parsed_input_holder_binding_jwt.deserialize(
            self._unverified_input_holder_binding_jwt
        )

        if not self._holder_public_key_payload:
            raise ValueError("No holder public key in SD-JWT")

        holder_public_key_payload_jwk = self._holder_public_key_payload.get("jwk", None)
        if not holder_public_key_payload_jwk:
            raise ValueError(
                "The holder_public_key_payload is malformed. "
                "It doesn't contain the claim jwk: "
                f"{self._holder_public_key_payload}"
            )

        pubkey = JWK.from_json(dumps(holder_public_key_payload_jwk))

        parsed_input_holder_binding_jwt.verify(pubkey, alg=_alg)

        holder_binding_jwt_payload = loads(parsed_input_holder_binding_jwt.payload)

        if holder_binding_jwt_payload["aud"] != expected_aud:
            raise ValueError("Invalid audience")
        if holder_binding_jwt_payload["nonce"] != expected_nonce:
            raise ValueError("Invalid nonce")

    def _extract_sd_claims(self):
        if DIGEST_ALG_KEY in self._sd_jwt_payload:
            if self._sd_jwt_payload[DIGEST_ALG_KEY] != self.HASH_ALG["name"]:
                # TODO: Support other hash algorithms
                raise ValueError("Invalid hash algorithm")

        self._duplicate_hash_check = []
        return self._unpack_disclosed_claims(self._sd_jwt_payload)

    def _unpack_disclosed_claims(self, sd_jwt_claims):
        # In a list, unpack each element individually
        if type(sd_jwt_claims) is list:
            return [self._unpack_disclosed_claims(c) for c in sd_jwt_claims]

        elif type(sd_jwt_claims) is dict:
            # First, try to figure out if there are any claims to be
            # disclosed in this dict. If so, replace them by their
            # disclosed values.

            pre_output = {
                k: self._unpack_disclosed_claims(v)
                for k, v in sd_jwt_claims.items()
                if k != SD_DIGESTS_KEY
            }

            for digest in sd_jwt_claims.get(SD_DIGESTS_KEY, []):
                if digest in self._duplicate_hash_check:
                    raise ValueError(f"Duplicate hash found in SD-JWT: {digest}")
                self._duplicate_hash_check.append(digest)

                if digest in self._hash_to_decoded_disclosure:
                    _, key, value = self._hash_to_decoded_disclosure[digest]
                    if key in pre_output:
                        raise ValueError(
                            f"Duplicate key found when unpacking disclosed claim: '{key}' in {pre_output}. This is not allowed."
                        )
                    unpacked_value = self._unpack_disclosed_claims(value)
                    pre_output[key] = unpacked_value

            # Now, go through the dict and unpack any nested dicts.

            return pre_output

        else:
            return sd_jwt_claims

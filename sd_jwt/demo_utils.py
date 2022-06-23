import json
import logging
import random

from jwcrypto.jwk import JWK
from typing import Union

logger = logging.getLogger(__name__)


def print_repr(values: Union[str, list], nlines=2):
    value = '\n'.join(values) if isinstance(values, (list, tuple)) else values
    _nlines = '\n' * nlines if nlines else ""
    print(f"{value}{_nlines}")


def get_jwk(jwk_kwargs: dict = {}, no_randomness: bool = False):
    """
    jwk_kwargs = {
        iss_key:dict : {},
        holder_key:dict : {},
        key_size: int : 0,
        kty: str : "RSA"
    }

    returns static or random JWK
    """
    random.seed(0)
    if no_randomness:
        ISSUER_KEY = JWK.from_json(json.dumps(jwk_kwargs['iss_key']))
        HOLDER_KEY = JWK.from_json(json.dumps(jwk_kwargs['holder_key']))
        logger.warning("Using fixed randomness for demo purposes")
    else:
        _kwargs = {
            "key_size": jwk_kwargs['key_size'], "kty": jwk_kwargs['kty']}
        ISSUER_KEY = JWK.generate(**_kwargs)
        HOLDER_KEY = JWK.generate(**_kwargs)

    ISSUER_PUBLIC_KEY = JWK.from_json(ISSUER_KEY.export_public())
    return dict(
        ISSUER_KEY=ISSUER_KEY,
        HOLDER_KEY=HOLDER_KEY,
        ISSUER_PUBLIC_KEY=ISSUER_PUBLIC_KEY
    )

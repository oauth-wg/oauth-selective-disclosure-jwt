from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from json import dumps
from hashlib import sha256
from base64 import b64encode, urlsafe_b64encode
import random

# Create the issuer's key in JWK format
issuer_key = JWK.generate(key_size=2048, kty="RSA")

# Create the holder's key in JWK format
holder_key = JWK.generate(key_size=2048, kty="RSA")

# Define the claims
full_user_claims = {
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
    return b64encode(bytes(random.getrandbits(8) for _ in range(16))).decode("ascii")


salts = {name: generate_salt() for name in full_user_claims}

#######################################################################

print("# Creating the JWS-SD")


def hash_claim(salt, value, return_raw=False):
    raw = dumps([salt, value])
    if return_raw:
        return raw
    # Calculate the SHA 256 hash and output it base64 encoded
    return b64encode(sha256(raw.encode("utf-8")).digest()).decode("ascii")


jws_sd_doc = {
    "iss": "https://example.com/issuer",
    "sub_jwk": issuer_key.export_public(as_dict=True),
    "iat": 1516239022,
    "exp": 1516247022,
    "sd_claims": {
        name: hash_claim(salts[name], value) for name, value in full_user_claims.items()
    },
}

print("Contents of the JWS-SD:\n```\n" + dumps(jws_sd_doc, indent=4) + "\n```\n\n")

# Sign the JWS-SD using the issuer's key
jws_sd = JWS(payload=dumps(jws_sd_doc))
jws_sd.add_signature(issuer_key, alg="RS256", protected=dumps({"alg": "RS256"}))
print("The serialized JWS-SD:\n```\n" + jws_sd.serialize(compact=True) + "\n```\n\n")

svc = {
    name: hash_claim(salts[name], value, return_raw=True)
    for name, value in full_user_claims.items()
}
print("Contents of the JWS-SD SVC:\n```\n" + dumps(svc, indent=4) + "\n```\n\n")

print("The serialized JWS-SD SVC:\n```\n" + urlsafe_b64encode(dumps(svc, indent=4).encode('utf-8')).decode('ascii').strip('=') + "\n```\n\n")

#######################################################################

print("# Creating the JWS-SD-Proof")

disclosed_claims = ["family_name", "address"]

jws_sd_p_doc = {
    "nonce": random.randint(0, 1000000),
    "sd": {
        name: hash_claim(salts[name], full_user_claims[name], return_raw=True)
        for name in disclosed_claims
    },
}

print(
    "Contents of the JWS-SD-Proof:\n```\n" + dumps(jws_sd_p_doc, indent=4) + "\n```\n\n"
)


# Sign the JWS-SD-Proof using the holder's key
jws_sd_p = JWS(payload=dumps(jws_sd_p_doc))
jws_sd_p.add_signature(holder_key, alg="RS256", protected=dumps({"alg": "RS256"}))

print(
    "The serialized JWS-SD-Proof:\n```\n"
    + jws_sd_p.serialize(compact=True)
    + "\n```\n\n"
)

#######################################################################

print("# Creating the Combined Representation")
# Combine both documents!
both = jws_sd.serialize(compact=True) + "." + jws_sd_p.serialize(compact=True)

print("Combined Representation:\n```\n" + both + "\n```\n\n")

import random
from base64 import urlsafe_b64encode


def pad_urlsafe_b64(value: str):
    return f"{value}{'=' * divmod(len(value),4)[1]}"


# The salts will be selected by the server, of course.
def generate_salt():
    return (
        urlsafe_b64encode(bytes(random.getrandbits(8) for _ in range(16)))
        .decode("ascii")
        .strip("=")
    )

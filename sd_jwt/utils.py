import base64


def pad_urlsafe_b64(value: str):
    return f"{value}{'=' * divmod(len(value),4)[1]}"

from base64 import b64encode


def get_content(file_name: str) -> bytes:
    with open(file_name, 'rb') as f:
        return f.read()


def get_content_b64(filename):
    return b64encode(get_content(filename))

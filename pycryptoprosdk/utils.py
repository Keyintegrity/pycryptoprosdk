import binascii
from base64 import b64decode
from typing import Union

from pycryptoprosdk.exceptions import PyCryptoproException


def prepare_message(
        message: Union[str, bytes],
        decode_b64: bool = False,
) -> bytes:
    if isinstance(message, str):
        message = message.encode('utf-8')
    if decode_b64:
        try:
            message = b64decode(message)
        except (binascii.Error, TypeError):
            raise PyCryptoproException('Incorrect base64 string.') from None
    return message

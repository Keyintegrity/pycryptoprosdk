from typing import Union

from pycryptoprosdk import libpycades
from .datatypes import (
    CertInfo,
    VerificationInfo,
    VerificationInfoDetached,
)
from .utils import prepare_message


class Signature:
    def verify(self, signature: Union[str, bytes]) -> VerificationInfo:
        """Верифицирует присоединенную подпись.

        :param signature: контент подписи, закодированный в base64
        :return: VerificationInfo
        """
        signature = prepare_message(signature, decode_b64=True)
        res = libpycades.verify(signature)
        return VerificationInfo(res)

    def verify_detached(
            self,
            message: Union[str, bytes],
            signature: Union[str, bytes],
    ) -> VerificationInfoDetached:
        """Верифицирует отсоединенную подпись.

        :param message: сообщение, для которого проверяется подпись
        :param signature: контент подписи, закодированный в base64
        :return: объект VerificationInfoDetached
        """
        message = prepare_message(message)
        signature = prepare_message(signature, decode_b64=True)
        res = libpycades.verify_detached(message, signature)
        return VerificationInfoDetached(res)

    def get_signer_cert(self, signature: Union[str, bytes]) -> CertInfo:
        """Извлекает сертификат подписанта из подписи.

        :param signature: контент подписи в base64
        :return: объект CertInfo
        """
        signature = prepare_message(signature, decode_b64=True)
        return CertInfo(libpycades.get_signer_cert_from_signature(signature))

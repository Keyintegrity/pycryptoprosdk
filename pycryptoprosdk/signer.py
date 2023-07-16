from typing import Union

from pycryptoprosdk import libpycades
from pycryptoprosdk.utils import prepare_message
from .datatypes import CproStore


class Signer:
    def sign(
            self,
            message: Union[str, bytes],
            thumbprint: str,
            detached: bool = False,
    ) -> bytes:
        """Создает подпись.

        :param message: подписываемое сообщение
        :param thumbprint: отпечаток сертификата из хранилища `uMy`, которым производится подписание
        :param detached: создавать отсоединенную подпись
        :return: подпись в base64
        """
        message = prepare_message(message)
        return libpycades.sign(
            message,
            thumbprint,
            CproStore.U_MY.store_name,
            detached,
        )

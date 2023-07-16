from typing import Union

from pycryptoprosdk import libpycades
from .utils import prepare_message


class Hash:
    def create_hash(
            self,
            message: Union[str, bytes],
            alg: str,
    ) -> str:
        """Вычисляет хэш сообщения по ГОСТу.

        :param message: сообщение
        :param alg: алгоритм хэширования.
            Возможные значения: 'CALG_GR3411', 'CALG_GR3411_2012_256', 'CALG_GR3411_2012_512'
        :return: хэш-значение
        """
        available_alg = (
            'CALG_GR3411',
            'CALG_GR3411_2012_256',
            'CALG_GR3411_2012_512',
        )
        if alg not in available_alg:
            raise ValueError('Unexpected algorithm \'{}\''.format(alg))

        return libpycades.create_hash(prepare_message(message), alg)

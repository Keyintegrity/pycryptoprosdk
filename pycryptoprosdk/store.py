from typing import Union

from pycryptoprosdk import libpycades
from .datatypes import CproStore, CertInfo
from .utils import prepare_message


class AbstractCertStore:
    store: CproStore = None

    def get_cert_by_subject(self, subject: str) -> CertInfo:
        """Возвращает сертификат по subject.

        :param subject: subject сертификата
        :return: объект CertInfo
        """
        return CertInfo(libpycades.get_cert_by_subject(
            self.store.store_name,
            subject,
            self.store.store_type.value,
        ))

    def get_cert_by_thumbprint(self, thumbprint: str) -> CertInfo:
        """Получает сертификат по отпечатку.

        :param thumbprint: отпечаток сертификата
        :return: объект CertInfo
        """
        return CertInfo(libpycades.get_cert_by_thumbprint(
            self.store.store_name,
            thumbprint,
            self.store.store_type.value,
        ))

    def install_certificate(self, cert_content: Union[str, bytes]) -> CertInfo:
        """Устанавливает сертификат в хранилище сертификатов.

        :param cert_content: контент сертификата, закодированный в base64
        :return: объект CertInfo
        """
        cert_content = prepare_message(cert_content, decode_b64=True)
        return CertInfo(libpycades.install_certificate(
            self.store.store_name,
            cert_content,
            self.store.store_type.value,
        ))

    def delete_certificate(self, thumbprint: str) -> None:
        """Удаляет сертификат из хранилища сертификатов.

        :param thumbprint: отпечаток сертификата
        """
        libpycades.delete_certificate(
            self.store.store_name,
            thumbprint,
            self.store.store_type.value,
        )


class MRootStore(AbstractCertStore):
    store = CproStore.M_ROOT


class URootStore(AbstractCertStore):
    store = CproStore.U_ROOT


class MCAStore(AbstractCertStore):
    store = CproStore.M_CA


class UCAStore(AbstractCertStore):
    store = CproStore.U_CA


class MMyStore(AbstractCertStore):
    store = CproStore.M_MY


class UMyStore(AbstractCertStore):
    store = CproStore.U_MY

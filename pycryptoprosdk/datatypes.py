from base64 import b64decode
from enum import Enum
from functools import cached_property


class StoreType(Enum):
    USER = 0
    MACHINE = 1


class CproStore(Enum):
    M_ROOT = 'ROOT', StoreType.MACHINE
    U_ROOT = 'ROOT', StoreType.USER
    M_CA = 'CA', StoreType.MACHINE
    U_CA = 'CA', StoreType.USER
    M_MY = 'MY', StoreType.MACHINE
    U_MY = 'MY', StoreType.USER

    @property
    def store_name(self) -> str:
        return self.value[0]

    @property
    def store_type(self) -> StoreType:
        return self.value[1]


class CertName:
    def __init__(self, cert_name_string):
        self.cert_name = cert_name_string

    def __repr__(self):
        return self.text

    def __len__(self):
        return len(self.text)

    @cached_property
    def text(self) -> str:
        return self.cert_name.replace('\r\n', ', ')

    @cached_property
    def data(self) -> dict:
        data = {}
        for item in self.cert_name.split('\r\n'):
            try:
                k, v = item.split('=')
                data[k] = v
            except:
                pass
        return data


class Subject(CertName):
    def __init__(self, cert_name_string: str):
        super(Subject, self).__init__(cert_name_string)

    @property
    def cn(self) -> str:
        return self._get_field('CN')

    @property
    def inn_original(self) -> str:
        return self._get_field('INN')

    @property
    def inn(self) -> str:
        if len(self.inn_original) == 12 and self.inn_original[:2] == '00':
            return self.inn_original[2:]
        return self.inn_original

    @property
    def snils(self) -> str:
        return self._get_field('SNILS')

    @property
    def city(self) -> str:
        return self._get_field('L')

    @property
    def street(self) -> str:
        return self._get_field('STREET')

    @property
    def ogrn(self) -> str:
        return self._get_field('OGRN')

    def _get_field(self, field_name: str):
        return self.data.get(field_name, '')


class Issuer(Subject):
    pass


class CertInfo:
    def __init__(self, cert_info: dict):
        self.cert_info = cert_info
        self.subject = Subject(cert_info['subject'])
        self.issuer = Issuer(cert_info['issuer'])
        self.valid_from = cert_info['notValidBefore']
        self.valid_to = cert_info['notValidAfter']
        self.thumbprint = cert_info['thumbprint']

        alt_name = cert_info['altName']
        self.alt_name = CertName(alt_name) if alt_name else None


class VerificationInfoDetached:
    def __init__(self, verification_info: dict):
        self._verification_info = verification_info

        self.verification_status = self._verification_info['verificationStatus']
        self.cert = self._get_cert()
        self.error = self._verification_info['error']

    def _get_cert(self) -> CertInfo | None:
        if self.verification_status == -1:
            return
        return CertInfo(self._verification_info['certInfo'])


class VerificationInfo(VerificationInfoDetached):
    def __init__(self, verification_info):
        super(VerificationInfo, self).__init__(verification_info)
        message = self._verification_info['message']
        self.message = b64decode(message) if message else None

    def _get_cert(self) -> CertInfo | None:
        if self.verification_status == -1:
            return
        return CertInfo(self._verification_info['certInfo'])

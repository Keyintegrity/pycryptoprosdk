import binascii
from base64 import b64decode

from pycryptoprosdk import libpycades
from pycryptoprosdk.exceptions import PyCryptoproException


class CryptoProSDK:
    def sign(self, message, thumbprint, store='MY', detached=False):
        """Создает подпись.

        :param message: подписываемое сообщение
        :param thumbprint: отпечаток сертификата, которым производится подписание
        :param store: хранилище сертификата, которым производится подписание
        :param detached: создавать отсоединенную подпись
        :return: подпись в base64
        """
        message = self._prepare_message(message)
        return libpycades.sign(message, thumbprint, store, detached)

    def verify(self, signature):
        """Верифицирует присоединенную подпись.

        :param signature: контент подписи, закодированный в base64
        :return: VerificationInfo
        """
        signature = self._prepare_message(signature, decode_b64=True)
        res = libpycades.verify(signature)
        return VerificationInfo(res)

    def verify_detached(self, message, signature):
        """Верифицирует отсоединенную подпись.

        :param message: сообщение, для которого проверяется подпись
        :param signature: контент подписи, закодированный в base64
        :return: объект VerificationInfoDetached
        """
        message = self._prepare_message(message)
        signature = self._prepare_message(signature, decode_b64=True)
        res = libpycades.verify_detached(message, signature)
        return VerificationInfoDetached(res)

    def create_hash(self, message, alg):
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

        return libpycades.create_hash(self._prepare_message(message), alg)

    def get_cert_by_subject(self, store, subject, store_type=0):
        """Возвращает сертификат по subject.

        :param store: имя хранилища сертификатов
        :param subject: subject сертификата
        :param store_type: тип хранилища (0 - CURRENT_USER, 1 - LOCAL_MACHINE)
        :return: объект CertInfo
        """
        return CertInfo(libpycades.get_cert_by_subject(store, subject, store_type))

    def get_cert_by_thumbprint(self, store, thumbprint, store_type=0):
        """Получает сертификат по отпечатку.

        :param store: имя хранилища сертификатов
        :param thumbprint: отпечаток сертификата
        :param store_type: тип хранилища (0 - CURRENT_USER, 1 - LOCAL_MACHINE)
        :return: объект CertInfo
        """
        return CertInfo(libpycades.get_cert_by_thumbprint(store, thumbprint, store_type))

    def install_certificate(self, store_name, cert_content, store_type=0):
        """Устанавливает сертификат в хранилище сертификатов.

        :param store_name: имя хранилища сертификатов
        :param cert_content: контент сертификата, закодированный в base64
        :param store_type: тип хранилища (0 - CURRENT_USER, 1 - LOCAL_MACHINE)
        :return: объект CertInfo
        """
        cert_content = self._prepare_message(cert_content, decode_b64=True)
        return libpycades.install_certificate(store_name, cert_content, store_type)

    def delete_certificate(self, store_name, thumbprint, store_type=0):
        """Удаляет сертификат из хранилища сертификатов.

        :param store_name: имя хранилища сертификатов
        :param thumbprint: отпечаток сертификата
        :param store_type: тип хранилища (0 - CURRENT_USER, 1 - LOCAL_MACHINE)
        """
        libpycades.delete_certificate(store_name, thumbprint, store_type)

    def get_signer_cert_from_signature(self, signature):
        """Извлекает сертификат подписанта из подписи.

        :param signature: контент подписи в base64
        :return: объект CertInfo
        """
        signature = self._prepare_message(signature, decode_b64=True)
        return CertInfo(libpycades.get_signer_cert_from_signature(signature))

    def _prepare_message(self, message, decode_b64=False):
        if isinstance(message, str):
            message = message.encode('utf-8')
        if decode_b64:
            try:
                message = b64decode(message)
            except (binascii.Error, TypeError):
                raise PyCryptoproException('Incorrect base64 string.') from None
        return message


class CertName:
    def __init__(self, cert_name_string):
        self.cert_name = cert_name_string

    def __repr__(self):
        return self.as_string()

    def __len__(self):
        return len(self.as_string())

    def as_string(self):
        return self.cert_name.replace('\r\n', ', ')

    def as_dict(self):
        data = {}
        for item in self.cert_name.split('\r\n'):
            try:
                k, v = item.split('=')
                data[k] = v
            except:
                pass
        return data


class Subject(CertName):
    def __init__(self, cert_name_string):
        super(Subject, self).__init__(cert_name_string)

        self.personal_info = self.as_dict()


class Issuer(Subject):
    pass


class CertInfo:
    def __init__(self, cert_info):
        self.cert_info = cert_info
        self.subject = Subject(cert_info['subject'])
        self.issuer = Issuer(cert_info['issuer'])
        self.valid_from = cert_info['notValidBefore']
        self.valid_to = cert_info['notValidAfter']
        self.thumbprint = cert_info['thumbprint']

        alt_name = cert_info['altName']
        self.alt_name = CertName(alt_name) if alt_name else None

    def as_dict(self):
        return self.cert_info


class VerificationInfoDetached:
    def __init__(self, verification_info):
        self._verification_info = verification_info

        self.verification_status = self._verification_info['verificationStatus']
        self.cert = self._get_cert()
        self.error = self._verification_info['error']

    def _get_cert(self):
        if self.verification_status == -1:
            return
        return CertInfo(self._verification_info['certInfo'])


class VerificationInfo(VerificationInfoDetached):
    def __init__(self, verification_info):
        super(VerificationInfo, self).__init__(verification_info)
        message = self._verification_info['message']
        self.message = b64decode(message) if message else None

    def _get_cert(self):
        if self.verification_status == -1:
            return
        return CertInfo(self._verification_info['certInfo'])

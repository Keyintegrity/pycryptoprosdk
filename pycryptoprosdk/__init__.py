from base64 import b64decode
from pycryptoprosdk import libpycades


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

    def get_cert_by_subject(self, store, subject):
        """Возвращает сертификат по subject.

        :param store: имя хранилища сертификатов
        :param subject: subject сертификата
        :return: объект CertInfo
        """
        return CertInfo(libpycades.get_cert_by_subject(store, subject))

    def get_cert_by_thumbprint(self, store, thumbprint):
        """Получает сертификат по отпечатку.

        :param store: имя хранилища сертификатов
        :param thumbprint: отпечаток сертификата
        :return: объект CertInfo
        """
        return CertInfo(libpycades.get_cert_by_thumbprint(store, thumbprint))

    def install_certificate(self, store_name, cert_content):
        """Устанавливает сертификат в хранилище сертификатов.

        :param store_name: имя хранилища сертификатов
        :param cert_content: контент сертификата, закодированный в base64
        :return: объект CertInfo
        """
        cert_content = self._prepare_message(cert_content, decode_b64=True)
        return libpycades.install_certificate(store_name, cert_content)

    def delete_certificate(self, store_name, thumbprint):
        """Удаляет сертификат из хранилища сертификатов.

        :param store_name: имя хранилища сертификатов
        :param thumbprint: отпечаток сертификата
        """
        libpycades.delete_certificate(store_name, thumbprint)

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
            message = b64decode(message)
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
        self.cn = self._get_field('CN')
        self.inn_original = self._get_field('INN')
        self.inn = self.inn_original
        if len(self.inn_original) == 12 and self.inn_original[:2] == '00':
            self.inn = self.inn_original[2:]
        self.snils = self._get_field('SNILS')
        self.city = self._get_field('L')
        self.street = self._get_field('STREET')

    def _get_field(self, name):
        return self.personal_info.get(name, '')


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

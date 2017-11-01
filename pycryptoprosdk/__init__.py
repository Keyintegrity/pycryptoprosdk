import ctypes
import os
from distutils.sysconfig import get_config_var
from pycryptoprosdk.utils import str_to_date


class _CertInfo(ctypes.Structure):
    _fields_ = [
        ('subject', ctypes.c_char * 1024),
        ('issuer', ctypes.c_char * 1024),
        ('notValidBefore', ctypes.c_char * 19),
        ('notValidAfter', ctypes.c_char * 19),
        ('thumbprint', ctypes.c_char * 41)
    ]


class _VerificationInfo(ctypes.Structure):
    _fields_ = [
        ('verificationStatus', ctypes.c_int),
        ('error', ctypes.c_char * 1024),
        ('certInfo', _CertInfo)
    ]


class Subject(object):
    def __init__(self, subject_string):
        self.subject_string = subject_string

    def as_string(self):
        return self.subject_string

    def as_dict(self):
        return self._parse(self.subject_string)

    @staticmethod
    def _parse(line):
        data = {}
        for item in line.split(', '):
            try:
                k, v = item.split('=')
                data[k] = v
            except:
                pass
        return data

    def __repr__(self):
        return self.as_string()

    def __len__(self):
        return len(self.as_string())


class CertInfo(object):
    def __init__(self, cert_info):
        self.subject = Subject(cert_info.subject.decode('utf-8'))
        self.issuer = Subject(cert_info.issuer.decode('utf-8'))
        self.valid_from = str_to_date(cert_info.notValidBefore.decode('utf-8'))
        self.valid_to = str_to_date(cert_info.notValidAfter.decode('utf-8'))
        self.thumbprint = cert_info.thumbprint.decode('utf-8')


class VerificationInfo(object):
    def __init__(self, verification_info):
        self._verification_info = verification_info

        self.verification_status = self._verification_info.verificationStatus
        self.cert = self._get_cert()
        self.error = self._verification_info.error.decode('utf-8')

    def _get_cert(self):
        if self.verification_status == -1:
            return
        return CertInfo(self._verification_info.certInfo)


class CryptoProSDK(object):
    def __init__(self):
        suffix = get_config_var('EXT_SUFFIX') or ''

        dirname = os.path.dirname(os.path.realpath(__file__))
        self.lib = ctypes.CDLL(os.path.join(dirname, 'libpycades{}{}'.format(suffix, '.so' if not suffix else '')))

        self._verify_detached = self.lib.VerifyDetached
        self._verify_detached.restype = _VerificationInfo

        self._create_hash = self.lib.CreateHash
        self._create_hash.restype = ctypes.c_bool

        self._get_cert_by_subject = self.lib.GetCertBySubject
        self._get_cert_by_subject.restype = ctypes.c_bool

        self._get_cert_by_thumbprint = self.lib.GetCertByThumbprint
        self._get_cert_by_thumbprint.restype = ctypes.c_bool

        self._install_certificate = self.lib.InstallCertificate
        self._install_certificate.restype = ctypes.c_bool

        self._delete_certificate = self.lib.DeleteCertificate
        self._delete_certificate.restype = ctypes.c_bool

        self._get_issuer_cert_from_signature = self.lib.GetSignerCertFromSignature
        self._get_issuer_cert_from_signature.restype = ctypes.c_bool

    def verify_detached(self, file_content, signature_content):
        """
        Верифицирует отсоединенную подпись
        :param file_content: контент файла, закодированный в base64
        :param signature_content: контент подписи, закодированный в base64
        :return: структура VerificationInfo
        """
        res = self._verify_detached(file_content, signature_content)
        return VerificationInfo(res)

    def create_hash(self, content):
        """
        Вычисляет хэш сообщения по ГОСТу
        :param content: сообщение
        :return: хэш-значение
        """
        h = (ctypes.c_char*64)()
        res = self._create_hash(content, len(content), ctypes.byref(h))
        if res:
            return h.value.upper().decode('utf-8')

    def get_cert_by_subject(self, store, subject):
        """
        Возвращает сертификат по subject
        :param store: имя хранилища сертификатов
        :param subject: subject сертификата
        :return: объект CertInfo
        """
        cert_info = _CertInfo()
        res = self._get_cert_by_subject(store.encode('utf-8'), subject.encode('utf-8'), ctypes.byref(cert_info))
        if res:
            return CertInfo(cert_info)

    def get_cert_by_thumbprint(self, store, thumbprint):
        """
        Получает сертификат по отпечатку
        :param store: имя хранилища сертификатов
        :param thumbprint: отпечаток сертификата
        :return: объект CertInfo
        """
        cert_info = _CertInfo()
        res = self._get_cert_by_thumbprint(store.encode('utf-8'), thumbprint.encode('utf-8'), ctypes.byref(cert_info))
        if res:
            return CertInfo(cert_info)

    def install_certificate(self, store_name, cert_content):
        """
        Устанавливает сертификат в хранилище сертификатов
        :param store_name: имя хранилища сертификатов
        :param cert_content: контент сертификата, закодированный в base64
        :return: True в случае успеха, False в случае неудачи
        """
        return self._install_certificate(store_name.encode('utf-8'), cert_content.encode('utf-8'))

    def delete_certificate(self, store_name, thumbprint):
        """
        Удаляет сертификат из хранилища сертификатов
        :param store_name: имя хранилища сертификатов
        :param thumbprint: отпечаток сертификата
        :return: True в случае успеха, False в случае неудачи
        """
        return self._delete_certificate(store_name.encode('utf-8'), thumbprint.encode('utf-8'))

    def get_signer_cert_from_signature(self, signature_content):
        """
        Извлекает сертификат подписанта из подписи
        :param signature_content: контент подписи,  в base64
        :return: объект CertInfo
        """
        cert_info = _CertInfo()
        res = self._get_issuer_cert_from_signature(signature_content, ctypes.byref(cert_info))
        if res:
            return CertInfo(cert_info)

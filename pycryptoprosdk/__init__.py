import ctypes
import os
import re

from distutils.sysconfig import get_config_var
from pycryptoprosdk.utils import str_to_date


class _CertInfo(ctypes.Structure):
    _fields_ = [
        ('subject', ctypes.c_char * 1024),
        ('issuer', ctypes.c_char * 1024),
        ('notValidBefore', ctypes.c_char * 19),
        ('notValidAfter', ctypes.c_char * 19),
        ('thumbprint', ctypes.c_char * 41),
        ('altName', ctypes.c_char * 1024),
    ]


class _VerificationInfo(ctypes.Structure):
    _fields_ = [
        ('verificationStatus', ctypes.c_int),
        ('error', ctypes.c_char * 1024),
        ('certInfo', _CertInfo)
    ]


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
        self.subject = Subject(cert_info.subject.decode('utf-8'))
        self.issuer = Issuer(cert_info.issuer.decode('utf-8'))
        self.valid_from = str_to_date(cert_info.notValidBefore.decode('utf-8'))
        self.valid_to = str_to_date(cert_info.notValidAfter.decode('utf-8'))
        self.thumbprint = cert_info.thumbprint.decode('utf-8')
        self.alt_name = CertName(cert_info.altName.decode('utf-8', errors='ignore'))


class VerificationInfo:
    def __init__(self, verification_info):
        self._verification_info = verification_info

        self.verification_status = self._verification_info.verificationStatus
        self.cert = self._get_cert()
        self.error = self._verification_info.error.decode('utf-8')

    def _get_cert(self):
        if self.verification_status == -1:
            return
        return CertInfo(self._verification_info.certInfo)


class CryptoProSDK:
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

    def create_hash(self, content, alg):
        """
        Вычисляет хэш сообщения по ГОСТу
        :param content: сообщение
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

        res_length = 64
        if alg == 'CALG_GR3411_2012_512':
            res_length = 128

        h = (ctypes.c_char*res_length)()
        res = self._create_hash(content, len(content), alg.encode('utf-8'), ctypes.byref(h))
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

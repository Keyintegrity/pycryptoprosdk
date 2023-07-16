import os
from base64 import b64encode
from unittest import TestCase

from pycryptoprosdk import Signature, Signer
from pycryptoprosdk.exceptions import PyCryptoproException
from pycryptoprosdk.store import UMyStore
from tests.utils import get_content

files_dir = os.path.join(os.path.dirname(__file__), 'files')


class SignAndVerifyTestCase(TestCase):
    def test_success(self):
        cert = UMyStore().get_cert_by_subject('pycryptoprosdk')
        signature = Signer().sign('qwerty', cert.thumbprint)
        res = Signature().verify(signature)

        self.assertEqual(res.verification_status, 0)
        self.assertIsNotNone(res.cert)
        self.assertEqual(res.message, b'qwerty')

        self.assertEqual(
            res.cert.issuer.as_string(),
            'E=support@cryptopro.ru, C=RU, L=Moscow, O=CRYPTO-PRO LLC, CN=CRYPTO-PRO Test Center 2'
        )
        self.assertEqual(
            res.cert.subject.as_string(),
            'CN=pycryptoprosdk, INN=123456789047, OGRN=1123300000053, SNILS=12345678901, STREET="Улица, дом", L=Город'
        )
        subject_dict = res.cert.subject.as_dict()
        self.assertEqual(subject_dict['CN'], 'pycryptoprosdk')
        self.assertEqual(subject_dict['INN'], '123456789047')
        self.assertEqual(subject_dict['OGRN'], '1123300000053')
        self.assertEqual(subject_dict['SNILS'], '12345678901')
        self.assertEqual(subject_dict['STREET'], '"Улица, дом"')
        self.assertEqual(subject_dict['L'], 'Город')

        self.assertEqual(res.cert.subject.personal_info, subject_dict)

        self.assertIsNone(res.cert.alt_name)
        self.assertIsNone(res.error)

    def test_verify_if_signature_is_not_base64(self):
        with self.assertRaises(PyCryptoproException) as context:
            Signature().verify(signature='123')
        self.assertEqual(str(context.exception), 'Incorrect base64 string.')

    def test_verify_if_signature_is_base64_but_not_signature(self):
        signature = b64encode(b'123')
        res = Signature().verify(signature=signature)
        self.assertEqual(res.verification_status, -1)
        self.assertIsNone(res.message)
        self.assertIsNone(res.cert)
        self.assertEqual(res.error, '0x80091004')

    def test_verify_if_signature_is_none(self):
        with self.assertRaises(PyCryptoproException) as context:
            Signature().verify(signature=None)
        self.assertEqual(str(context.exception), 'Incorrect base64 string.')

    def test_sign_file_content(self):
        content = get_content(os.path.join(files_dir, 'img.png'))
        cert = UMyStore().get_cert_by_subject('pycryptoprosdk')
        signature = Signer().sign(content, cert.thumbprint, detached=False)
        self.assertTrue(len(signature) > 0)

    def test_sign_message_as_string(self):
        cert = UMyStore().get_cert_by_subject('pycryptoprosdk')
        signature = Signer().sign('qwerty', cert.thumbprint, detached=False)
        self.assertTrue(len(signature) > 0)

    def test_sign_message_as_binary(self):
        cert = UMyStore().get_cert_by_subject('pycryptoprosdk')
        signature = Signer().sign(b'qwerty', cert.thumbprint, detached=False)
        self.assertTrue(len(signature) > 0)

    # def test_get_signer_alt_name_from_signature(self):
    #     signature_content = self._get_content(os.path.join(files_dir, 'signatures', 'test_alt_name.txt.sig'))
    #     cert = Signature().get_signer_cert(signature_content)
    #     self.assertDictEqual(cert.alt_name.as_dict(), {'OGRNIP': '123456789012345'})


class SignAndVerifyDetachedTestCase(TestCase):
    def test_success(self):
        content = b'test content'
        cert = UMyStore().get_cert_by_subject('pycryptoprosdk')
        signature = Signer().sign(content, cert.thumbprint, detached=True)

        res = Signature().verify_detached(content, signature)

        self.assertEqual(0, res.verification_status)
        self.assertIsNotNone(res.cert)

        self.assertEqual(
            res.cert.issuer.as_string(),
            'E=support@cryptopro.ru, C=RU, L=Moscow, O=CRYPTO-PRO LLC, CN=CRYPTO-PRO Test Center 2'
        )
        self.assertEqual(
            res.cert.subject.as_string(),
            'CN=pycryptoprosdk, INN=123456789047, OGRN=1123300000053, SNILS=12345678901, STREET="Улица, дом", L=Город'
        )
        subject_dict = res.cert.subject.as_dict()
        self.assertEqual(subject_dict['CN'], 'pycryptoprosdk')
        self.assertEqual(subject_dict['INN'], '123456789047')
        self.assertEqual(subject_dict['OGRN'], '1123300000053')
        self.assertEqual(subject_dict['SNILS'], '12345678901')
        self.assertEqual(subject_dict['STREET'], '"Улица, дом"')
        self.assertEqual(subject_dict['L'], 'Город')

        self.assertEqual(res.cert.subject.personal_info, subject_dict)
        self.assertIsNone(res.error)

    def test_verify_if_message_is_empty_string(self):
        cert = UMyStore().get_cert_by_subject('pycryptoprosdk')
        signature = Signer().sign('123', cert.thumbprint, detached=True)
        res = Signature().verify_detached(message='', signature=signature)
        self.assertEqual(res.verification_status, 8)
        self.assertIsNotNone(res.cert)
        self.assertEqual(res.error, '0x80090006')

    def test_verify_if_signature_is_empty_string(self):
        with self.assertRaises(PyCryptoproException) as context:
            Signature().verify_detached(message='', signature='123')
        self.assertEqual(str(context.exception), 'Incorrect base64 string.')

    def test_verify_if_signature_is_not_base64(self):
        with self.assertRaises(PyCryptoproException) as context:
            Signature().verify_detached(message='123', signature='123')
        self.assertEqual(str(context.exception), 'Incorrect base64 string.')

    def test_verify_if_signature_is_base64_but_not_signature(self):
        signature = b64encode(b'123')
        res = Signature().verify_detached(message='123', signature=signature)
        self.assertEqual(res.verification_status, -1)
        self.assertIsNone(res.cert)
        self.assertEqual(res.error, '0x80091004')

    def test_verify_if_signature_is_none(self):
        with self.assertRaises(PyCryptoproException) as context:
            Signature().verify_detached(message='123', signature=None)
        self.assertEqual(str(context.exception), 'Incorrect base64 string.')


class GetSignerCertFromSignatureTestCase(TestCase):
    def test_success(self):
        signature = get_content(os.path.join(files_dir, 'signatures', 'doc.txt.sig'))
        cert = Signature().get_signer_cert(signature)

        self.assertEqual(
            cert.issuer.as_string(),
            'E=support@cryptopro.ru, C=RU, L=Moscow, O=CRYPTO-PRO LLC, CN=CRYPTO-PRO Test Center 2'
        )
        self.assertEqual(
            cert.subject.as_string(),
            'CN=pycryptoprosdk, INN=123456789047, OGRN=1123300000053, SNILS=12345678901, STREET="Улица, дом", L=Город'
        )
        subject_dict = cert.subject.as_dict()
        self.assertEqual(
            subject_dict,
            {
                'CN': 'pycryptoprosdk',
                'INN': '123456789047',
                'OGRN': '1123300000053',
                'SNILS': '12345678901',
                'STREET': '"Улица, дом"',
                'L': 'Город',
            }
        )
        self.assertEqual(cert.subject.personal_info, subject_dict)
        self.assertIsNone(cert.alt_name)
        self.assertEqual(cert.subject.cn, 'pycryptoprosdk')
        self.assertEqual(cert.subject.inn_original, '123456789047')
        self.assertEqual(cert.subject.inn, '123456789047')
        self.assertEqual(cert.subject.ogrn, '1123300000053')
        self.assertEqual(cert.subject.snils, '12345678901')
        self.assertEqual(cert.subject.street, '"Улица, дом"')
        self.assertEqual(cert.subject.city, 'Город')

    def test_if_signature_is_empty_string(self):
        with self.assertRaises(PyCryptoproException) as context:
            Signature().get_signer_cert(signature='')
        self.assertEqual(str(context.exception), 'CryptMsgGetParam #1 failed.')

    def test_if_signature_is_not_base64(self):
        with self.assertRaises(PyCryptoproException) as context:
            Signature().get_signer_cert(signature='123')
        self.assertEqual('Incorrect base64 string.', str(context.exception))

    def test_if_signature_is_base64_but_not_signature(self):
        signature = b64encode(b'123')
        with self.assertRaises(PyCryptoproException) as context:
            Signature().get_signer_cert(signature=signature)
        self.assertEqual(str(context.exception), 'CryptMsgUpdate failed (error 0x80091004).')

    def test_if_signature_is_none(self):
        with self.assertRaises(PyCryptoproException) as context:
            Signature().get_signer_cert(signature=None)
        self.assertEqual(str(context.exception), 'Incorrect base64 string.')

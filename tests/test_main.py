import base64
import os
from base64 import b64encode
from datetime import datetime
from unittest import TestCase

from pycryptoprosdk.libpycades import PyCryptoproException, CertDoesNotExist

from pycryptoprosdk import CertName
from pycryptoprosdk import CryptoProSDK

files_dir = os.path.join(os.path.dirname(__file__), 'files')


class BaseTestCase(TestCase):
    def setUp(self):
        self.sdk = CryptoProSDK()

    def _get_content(self, file_name):
        with open(file_name, 'rb') as f:
            return f.read()


class TestCryptoProSDK(BaseTestCase):
    def _get_content_b64(self, filename):
        return b64encode(self._get_content(filename))

    def test_hash_CALG_GR3411(self):
        content = 'Данные для подписи\n'

        self.assertEqual(
            self.sdk.create_hash(content, 'CALG_GR3411'),
            '445888F2DEA25B3AD0187186CC18BD74D79CEF78498EF308755459AFE4552EBA'
        )

        content = self._get_content(os.path.join(files_dir, 'img.png'))

        self.assertEqual(
            self.sdk.create_hash(content, 'CALG_GR3411'),
            '799025F048414BD20681D41EDFEE3158D7D5B14DDCB17912E38DE0B620C353B7'
        )

    def test_hash_CALG_GR3411_2012_256(self):
        content = 'Данные для подписи\n'

        self.assertEqual(
            self.sdk.create_hash(content, 'CALG_GR3411_2012_256'),
            'AE943FBB2751DB601DEB5D90740CEA221B2EE0CD9A2A0D16E0F3A13DB78A02B5'
        )

    def test_hash_CALG_GR3411_2012_512(self):
        content = 'Данные для подписи\n'

        self.assertEqual(
            self.sdk.create_hash(content, 'CALG_GR3411_2012_512'),
            '32C1304E914F0616063D7765EBA5C81F907AB8CD684C0787ED9445DD74B8CD95A5C286B249EE338CFAA3F446057B6107E151596BC0240474BC342160F2440089'
        )

    def test_get_cert_by_thumbprint(self):
        cert = self.sdk.get_cert_by_thumbprint('ROOT', 'cd321b87fdabb503829f88db68d893b59a7c5dd3')
        self.assertIsNotNone(cert)
        self.assertEqual(
            cert.subject.as_string(),
            'E=support@cryptopro.ru, C=RU, L=Moscow, O=CRYPTO-PRO LLC, CN=CRYPTO-PRO Test Center 2'
        )
        self.assertEqual(
            cert.issuer.as_string(),
            'E=support@cryptopro.ru, C=RU, L=Moscow, O=CRYPTO-PRO LLC, CN=CRYPTO-PRO Test Center 2'
        )
        self.assertEqual(
            cert.valid_from,
            datetime(2019, 5, 27, 7, 24, 26)
        )
        self.assertEqual(
            cert.valid_to,
            datetime(2024, 5, 26, 7, 34, 5)
        )
        self.assertEqual(cert.thumbprint.lower(), 'cd321b87fdabb503829f88db68d893b59a7c5dd3')

    def test_get_cert_by_subject(self):
        cert = self.sdk.get_cert_by_subject(
            store='ROOT',
            subject='CRYPTO-PRO Test Center 2',
            store_type=0,
        )
        self.assertIsNotNone(cert)

        self.assertEqual(
            cert.issuer.as_string(),
            'E=support@cryptopro.ru, C=RU, L=Moscow, O=CRYPTO-PRO LLC, CN=CRYPTO-PRO Test Center 2'
        )

    def test_subject_data(self):
        cert = self.sdk.get_cert_by_thumbprint('ROOT', 'cd321b87fdabb503829f88db68d893b59a7c5dd3')
        subject_data = cert.subject.as_dict()
        self.assertIn('CN', subject_data)
        self.assertEqual(subject_data['CN'], 'CRYPTO-PRO Test Center 2')

    def test_install_and_delete_certificate(self):
        store = 'MY'
        thumbprint = '9e78a331020e528c046ffd57704a21b7d2241cb3'

        with self.assertRaises(CertDoesNotExist) as context:
            self.sdk.get_cert_by_thumbprint(store, thumbprint)
        self.assertTrue('Could not find the desired certificate.' in str(context.exception))

        cert_str = self._get_content_b64(os.path.join(files_dir, 'certs', 'uc_1_is_guc.cer'))
        res = self.sdk.install_certificate('MY', cert_str.decode('utf-8'))
        self.assertEqual(
            res.subject.as_dict(),
            {
                'INN': '007710474375',
                'OGRN': '1047702026701',
                'E': 'dit@minsvyaz.ru',
                'STREET': '125375 г. Москва ул. Тверская д.7',
                'O': 'Минкомсвязь России',
                'L': 'Москва',
                'S': '77 г. Москва',
                'C': 'RU',
                'CN': 'УЦ 1 ИС ГУЦ',
            }
        )
        cert = self.sdk.get_cert_by_thumbprint(store, thumbprint)
        self.assertIsNotNone(cert)
        self.sdk.delete_certificate(store, thumbprint)

        with self.assertRaises(CertDoesNotExist) as context:
            self.sdk.get_cert_by_thumbprint(store, thumbprint)
        self.assertTrue('Could not find the desired certificate.' in str(context.exception))

    def test_sign_file_content(self):
        content = self._get_content(os.path.join(files_dir, 'img.png'))
        cert = self.sdk.get_cert_by_subject('MY', 'pycryptoprosdk')
        signature = self.sdk.sign(content, cert.thumbprint, 'MY', detached=False)
        self.assertTrue(len(signature) > 0)

    def test_sign_message_as_string(self):
        cert = self.sdk.get_cert_by_subject('MY', 'pycryptoprosdk')
        signature = self.sdk.sign('qwerty', cert.thumbprint, 'MY', detached=False)
        self.assertTrue(len(signature) > 0)

    def test_sign_message_as_binary(self):
        cert = self.sdk.get_cert_by_subject('MY', 'pycryptoprosdk')
        signature = self.sdk.sign(b'qwerty', cert.thumbprint, 'MY', detached=False)
        self.assertTrue(len(signature) > 0)

    # def test_get_signer_alt_name_from_signature(self):
    #     signature_content = self._get_content(os.path.join(files_dir, 'signatures', 'test_alt_name.txt.sig'))
    #     cert = self.sdk.get_signer_cert_from_signature(signature_content)
    #     self.assertDictEqual(cert.alt_name.as_dict(), {'OGRNIP': '123456789012345'})


class GetSignerCertFromSignatureTestCase(BaseTestCase):
    def test_success(self):
        signature = self._get_content(os.path.join(files_dir, 'signatures', 'doc.txt.sig'))
        cert = self.sdk.get_signer_cert_from_signature(signature)

        self.assertEqual(
            cert.issuer.as_string(),
            'E=support@cryptopro.ru, C=RU, L=Moscow, O=CRYPTO-PRO LLC, CN=CRYPTO-PRO Test Center 2'
        )
        self.assertEqual(
            cert.subject.as_string(),
            'CN=pycryptoprosdk, INN=123456789047, OGRN=1123300000053, SNILS=12345678901, STREET="Улица, дом", L=Город'
        )
        subject_dict = cert.subject.as_dict()
        self.assertEqual(subject_dict['CN'], 'pycryptoprosdk')
        self.assertEqual(subject_dict['INN'], '123456789047')
        self.assertEqual(subject_dict['OGRN'], '1123300000053')
        self.assertEqual(subject_dict['SNILS'], '12345678901')
        self.assertEqual(subject_dict['STREET'], '"Улица, дом"')
        self.assertEqual(subject_dict['L'], 'Город')

        self.assertEqual(cert.subject.personal_info, subject_dict)

        self.assertIsNone(cert.alt_name)

    def test_if_signature_is_empty_string(self):
        with self.assertRaises(PyCryptoproException) as context:
            self.sdk.get_signer_cert_from_signature(signature='')
        self.assertEqual(str(context.exception), 'CryptMsgGetParam #1 failed.')

    def test_if_signature_is_not_base64(self):
        with self.assertRaises(PyCryptoproException) as context:
            self.sdk.get_signer_cert_from_signature(signature='123')
        self.assertEqual('Incorrect base64 string.', str(context.exception))

    def test_if_signature_is_base64_but_not_signature(self):
        signature = base64.b64encode(b'123')
        with self.assertRaises(PyCryptoproException) as context:
            self.sdk.get_signer_cert_from_signature(signature=signature)
        self.assertEqual(str(context.exception), 'CryptMsgUpdate failed (error 0x80091004).')

    def test_if_signature_is_none(self):
        with self.assertRaises(PyCryptoproException) as context:
            self.sdk.get_signer_cert_from_signature(signature=None)
        self.assertEqual(str(context.exception), 'Incorrect base64 string.')


class SignAndVerifyTestCase(BaseTestCase):
    def test_success(self):
        cert = self.sdk.get_cert_by_subject('MY', 'pycryptoprosdk')

        signature = self.sdk.sign('qwerty', cert.thumbprint, 'MY')
        res = self.sdk.verify(signature)

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
            self.sdk.verify(signature='123')
        self.assertEqual(str(context.exception), 'Incorrect base64 string.')

    def test_verify_if_signature_is_base64_but_not_signature(self):
        signature = base64.b64encode(b'123')
        res = self.sdk.verify(signature=signature)
        self.assertEqual(res.verification_status, -1)
        self.assertIsNone(res.message)
        self.assertIsNone(res.cert)
        self.assertEqual(res.error, '0x80091004')

    def test_verify_if_signature_is_none(self):
        with self.assertRaises(PyCryptoproException) as context:
            self.sdk.verify(signature=None)
        self.assertEqual(str(context.exception), 'Incorrect base64 string.')


class SignAndVerifyDetachedTestCase(BaseTestCase):
    def test_success(self):
        content = b'test content'
        cert = self.sdk.get_cert_by_subject('MY', 'pycryptoprosdk')
        signature = self.sdk.sign(content, cert.thumbprint, 'MY', detached=True)

        res = self.sdk.verify_detached(content, signature)

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
        cert = self.sdk.get_cert_by_subject('MY', 'pycryptoprosdk')
        signature = self.sdk.sign('123', cert.thumbprint, 'MY', detached=True)
        res = self.sdk.verify_detached(message='', signature=signature)
        self.assertEqual(res.verification_status, 8)
        self.assertIsNotNone(res.cert)
        self.assertEqual(res.error, '0x80090006')

    def test_verify_if_signature_is_empty_string(self):
        with self.assertRaises(PyCryptoproException) as context:
            self.sdk.verify_detached(message='', signature='123')
        self.assertEqual(str(context.exception), 'Incorrect base64 string.')

    def test_verify_if_signature_is_not_base64(self):
        with self.assertRaises(PyCryptoproException) as context:
            self.sdk.verify_detached(message='123', signature='123')
        self.assertEqual(str(context.exception), 'Incorrect base64 string.')

    def test_verify_if_signature_is_base64_but_not_signature(self):
        signature = base64.b64encode(b'123')
        res = self.sdk.verify_detached(message='123', signature=signature)
        self.assertEqual(res.verification_status, -1)
        self.assertIsNone(res.cert)
        self.assertEqual(res.error, '0x80091004')

    def test_verify_if_signature_is_none(self):
        with self.assertRaises(PyCryptoproException) as context:
            self.sdk.verify_detached(message='123', signature=None)
        self.assertEqual(str(context.exception), 'Incorrect base64 string.')


class TestCertName(TestCase):
    def test_subject_as_string(self):
        cert_name = CertName('\r\n'.join([
            'CN=Иванов Иван Иванович',
            'INN=1234567890',
            'STREET=ул. Горшкова, дом 4, 1',
            '2.5.4.5="#1303323739"'
        ]))
        cert_name_dict = cert_name.as_dict()
        self.assertDictEqual(
            {
                'CN': 'Иванов Иван Иванович',
                'INN': '1234567890',
                '2.5.4.5': '"#1303323739"',
                'STREET': 'ул. Горшкова, дом 4, 1',
            },
            cert_name_dict,
        )

import os
import unittest

from base64 import b64encode
from datetime import datetime

from pycryptoprosdk import CryptoProSDK
from pycryptoprosdk import Subject
from pycryptoprosdk.error_codes import CRYPT_E_INVALID_MSG_TYPE

files_dir = os.path.join(os.path.dirname(__file__), 'files')


class TestCryptoProSDK(unittest.TestCase):
    def setUp(self):
        self.sdk = CryptoProSDK()

    def _get_content(self, file_name, mode='rb'):
        with open(file_name, mode) as f:
            return f.read()

    def _get_content_b64(self, filename, mode='rb'):
        return b64encode(self._get_content(filename, mode))

    def test_sign_and_verify(self):
        cert = self.sdk.get_cert_by_subject('MY', 'Ivan')
        message = 'qwerty'
        signature = self.sdk.sign(message, cert.thumbprint, 'MY', detached=False)
        res = self.sdk.verify(signature)
        self.assertEqual(res.verification_status, 0)
        self.assertIsNotNone(res.cert)
        self.assertEqual(res.message, message.encode('utf-8'))

    def test_verify_detached(self):
        content = self._get_content(os.path.join(files_dir, 'signatures', 'doc.txt'))
        signature = self._get_content(os.path.join(files_dir, 'signatures', 'doc.txt.sgn'))

        res = self.sdk.verify_detached(content, signature)

        self.assertEqual(0, res.verification_status)
        self.assertIsNotNone(res.cert)

    def test_bad_signature_verify_detached(self):
        content = self._get_content(os.path.join(files_dir, 'signatures', 'doc.txt'))

        res = self.sdk.verify_detached(content, b64encode(b'signature'))

        self.assertEqual(res.verification_status, -1)
        self.assertIsNone(res.cert)
        self.assertEqual(CRYPT_E_INVALID_MSG_TYPE, res.error)

    def test_bad_signature_verify(self):
        res = self.sdk.verify(b64encode(b'signature'))

        self.assertEqual(res.verification_status, -1)
        self.assertIsNone(res.cert)
        self.assertIsNone(res.message)
        self.assertEqual(CRYPT_E_INVALID_MSG_TYPE, res.error)

    def test_hash_CALG_GR3411(self):
        content = self._get_content(os.path.join(files_dir, 'signatures', 'doc.txt'))

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
        content = self._get_content(os.path.join(files_dir, 'signatures', 'doc.txt'))

        self.assertEqual(
            self.sdk.create_hash(content, 'CALG_GR3411_2012_256'),
            'AE943FBB2751DB601DEB5D90740CEA221B2EE0CD9A2A0D16E0F3A13DB78A02B5'
        )

    def test_hash_CALG_GR3411_2012_512(self):
        content = self._get_content(os.path.join(files_dir, 'signatures', 'doc.txt'))

        self.assertEqual(
            self.sdk.create_hash(content, 'CALG_GR3411_2012_512'),
            '32C1304E914F0616063D7765EBA5C81F907AB8CD684C0787ED9445DD74B8CD95A5C286B249EE338CFAA3F446057B6107E151596BC0240474BC342160F2440089'
        )

    def test_get_cert_by_thumbprint(self):
        cert = self.sdk.get_cert_by_thumbprint('ROOT', '046255290b0eb1cdd1797d9ab8c81f699e3687f3')
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
            datetime(2014, 8, 5, 13, 44, 24)
        )
        self.assertEqual(
            cert.valid_to,
            datetime(2019, 8, 5, 13, 54, 3)
        )
        self.assertEqual(cert.thumbprint.lower(), '046255290b0eb1cdd1797d9ab8c81f699e3687f3')

    def test_get_cert_by_subject(self):
        cert = self.sdk.get_cert_by_subject('ROOT', 'CRYPTO-PRO Test Center 2')
        self.assertIsNotNone(cert)

        self.assertEqual(
            cert.subject.as_string(),
            'E=support@cryptopro.ru, C=RU, L=Moscow, O=CRYPTO-PRO LLC, CN=CRYPTO-PRO Test Center 2'
        )

    def test_subject_data(self):
        cert = self.sdk.get_cert_by_thumbprint('ROOT', '046255290b0eb1cdd1797d9ab8c81f699e3687f3')
        subject_data = cert.subject.as_dict()
        self.assertIn('CN', subject_data)
        self.assertEqual(subject_data['CN'], 'CRYPTO-PRO Test Center 2')

    def test_install_and_delete_certificate(self):
        store = 'MY'
        thumbprint = '9e78a331020e528c046ffd57704a21b7d2241cb3'

        with self.assertRaises(Exception) as context:
            self.sdk.get_cert_by_thumbprint(store, thumbprint)
        self.assertTrue('Could not find the desired certificate.' in str(context.exception))

        cert_str = self._get_content_b64(os.path.join(files_dir, 'certs', 'uc_1_is_guc.cer'))
        self.sdk.install_certificate('MY', cert_str.decode('utf-8'))

        cert = self.sdk.get_cert_by_thumbprint(store, thumbprint)
        self.assertIsNotNone(cert)
        self.sdk.delete_certificate(store, thumbprint)

        with self.assertRaises(Exception) as context:
            cert = self.sdk.get_cert_by_thumbprint(store, thumbprint)
        self.assertTrue('Could not find the desired certificate.' in str(context.exception))

    def test_get_signer_certificate_from_signature(self):
        signature_content = self._get_content(os.path.join(files_dir, 'signatures', 'doc.txt.sgn'))
        cert = self.sdk.get_signer_cert_from_signature(signature_content)

        self.assertIsNone(cert.alt_name)

        self.assertEqual(
            cert.issuer.as_string(),
            'E=support@cryptopro.ru, C=RU, L=Moscow, O=CRYPTO-PRO LLC, CN=CRYPTO-PRO Test Center 2'
        )
        self.assertEqual(
            cert.subject.as_string(),
            'CN=Иванов Иван Иванович, INN=123456789047, OGRN=1123300000053, SNILS=12345678901, STREET="Улица, дом", '
            'L=Город'
        )
        subject_dict = cert.subject.as_dict()
        self.assertEqual(subject_dict['CN'], 'Иванов Иван Иванович')
        self.assertEqual(subject_dict['INN'], '123456789047')
        self.assertEqual(subject_dict['OGRN'], '1123300000053')
        self.assertEqual(subject_dict['SNILS'], '12345678901')
        self.assertEqual(subject_dict['STREET'], '"Улица, дом"')
        self.assertEqual(subject_dict['L'], 'Город')

        self.assertEqual(cert.subject.personal_info, subject_dict)
        self.assertEqual(cert.subject.cn, 'Иванов Иван Иванович')
        self.assertEqual(cert.subject.inn, '123456789047')
        self.assertEqual(cert.subject.snils, '12345678901')
        self.assertEqual(cert.subject.street, '"Улица, дом"')
        self.assertEqual(cert.subject.city, 'Город')

    def test_inn_original(self):
        signature_content = self._get_content(os.path.join(files_dir, 'signatures', 'doc.txt.sgn'))
        cert = self.sdk.get_signer_cert_from_signature(signature_content)
        subject_list = cert.subject.cert_name.split(', ')
        subject_list[1] = 'INN=003456789047'
        subject_string = ', '.join(subject_list)
        subject = Subject(subject_string)
        self.assertEqual(subject.inn_original, '003456789047')
        self.assertEqual(subject.inn, '3456789047')

    def test_sign_file_content(self):
        content = self._get_content(os.path.join(files_dir, 'img.png'))
        cert = self.sdk.get_cert_by_subject('MY', 'Ivan')
        signature = self.sdk.sign(content, cert.thumbprint, 'MY', detached=False)
        self.assertTrue(len(signature) > 0)

    def test_sign_message_as_string(self):
        cert = self.sdk.get_cert_by_subject('MY', 'Ivan')
        signature = self.sdk.sign('qwerty', cert.thumbprint, 'MY', detached=False)
        self.assertTrue(len(signature) > 0)

    def test_sign_message_as_binary(self):
        cert = self.sdk.get_cert_by_subject('MY', 'Ivan')
        signature = self.sdk.sign(b'qwerty', cert.thumbprint, 'MY', detached=False)
        self.assertTrue(len(signature) > 0)

    def test_sign_detached(self):
        content = b'test content'
        cert = self.sdk.get_cert_by_subject('MY', 'Ivan')
        signature = self.sdk.sign(content, cert.thumbprint, 'MY', detached=True)

        res = self.sdk.verify_detached(content, signature)

        self.assertEqual(0, res.verification_status)
        self.assertIsNotNone(res.cert)

    # def test_get_signer_alt_name_from_signature(self):
    #     signature_content = self._get_content(os.path.join(files_dir, 'signatures', 'test.txt.sig'))
    #     cert = self.sdk.get_signer_cert_from_signature(signature_content)
    #     self.assertDictEqual(cert.alt_name.as_dict(), {'OGRNIP': '123456789012345'})


if __name__ == '__main__':
    unittest.main()

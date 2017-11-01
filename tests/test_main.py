import os
import unittest
from base64 import b64encode
from datetime import datetime
from pycryptoprosdk import CryptoProSDK
from pycryptoprosdk.error_codes import CRYPT_E_INVALID_MSG_TYPE


files_dir = os.path.join(os.path.dirname(__file__), 'files')


class TestCryptoProSDK(unittest.TestCase):
    def setUp(self):
        self.sdk = CryptoProSDK()

    def _get_content(self, file_name):
        with open(file_name, 'rb') as f:
            return f.read()

    def _get_content_b64(self, filename):
        return b64encode(self._get_content(filename))

    def test_verify_detached(self):
        with open(os.path.join(files_dir, 'signatures', 'doc.txt'), 'rb') as f:
            content = b64encode(f.read())

        with open(os.path.join(files_dir, 'signatures', 'doc.txt.sig'), 'rb') as f:
            signature = f.read()

        res = self.sdk.verify_detached(content, signature)

        self.assertEqual(res.verification_status, 0)
        self.assertIsNotNone(res.cert)

    def test_bad_signature(self):
        with open(os.path.join(files_dir, 'signatures', 'doc.txt'), 'rb') as f:
            content = b64encode(f.read())

        res = self.sdk.verify_detached(content, 'signature')

        self.assertEqual(res.verification_status, -1)
        self.assertIsNone(res.cert)
        self.assertEqual(res.error, CRYPT_E_INVALID_MSG_TYPE)

    def test_hash(self):
        with open(os.path.join(files_dir, 'signatures', 'doc.txt'), 'rb') as f:
            content = f.read()

        self.assertEqual(
            self.sdk.create_hash(content),
            '445888F2DEA25B3AD0187186CC18BD74D79CEF78498EF308755459AFE4552EBA'
        )

        with open(os.path.join(files_dir, 'img.png'), 'rb') as f:
            content = f.read()

        self.assertEqual(
            self.sdk.create_hash(content),
            '799025F048414BD20681D41EDFEE3158D7D5B14DDCB17912E38DE0B620C353B7'
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

        cert = self.sdk.get_cert_by_subject('ROOT', 'support@cryptopro.ru')
        self.assertIsNotNone(cert)

    def test_subject_data(self):
        cert = self.sdk.get_cert_by_thumbprint('ROOT', '046255290b0eb1cdd1797d9ab8c81f699e3687f3')
        subject_data = cert.subject.as_dict()
        self.assertIn('CN', subject_data)
        self.assertEqual(subject_data['CN'], 'CRYPTO-PRO Test Center 2')

    def test_install_and_delete_certificate(self):
        with open(os.path.join(files_dir, 'certs', 'uc_1_is_guc.cer'), 'rb') as f:
            cert_str = f.read()

        self.sdk.install_certificate('CA', b64encode(cert_str).decode('utf-8'))

        cert = self.sdk.get_cert_by_thumbprint('CA', '9e78a331020e528c046ffd57704a21b7d2241cb3')
        self.assertIsNotNone(cert)
        self.assertTrue(self.sdk.delete_certificate('CA', '9e78a331020e528c046ffd57704a21b7d2241cb3'))

    def test_get_signer_certificate_from_signature(self):
        signature_content = self._get_content(os.path.join(files_dir, 'signatures', 'doc.txt.sig'))
        cert = self.sdk.get_signer_cert_from_signature(signature_content)
        self.assertIsNotNone(cert)
        self.assertEqual(
            cert.subject.as_string(),
            'E=inav@ivanov.ru, CN=Ivan, L=Ivanovo, C=RU'
        )
        self.assertEqual(
            cert.issuer.as_string(),
            'E=support@cryptopro.ru, C=RU, L=Moscow, O=CRYPTO-PRO LLC, CN=CRYPTO-PRO Test Center 2'
        )


if __name__ == '__main__':
    unittest.main()

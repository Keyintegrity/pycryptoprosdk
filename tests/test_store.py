import os
from datetime import datetime
from unittest import TestCase

from pycryptoprosdk import URootStore, UMyStore
from pycryptoprosdk.exceptions import CertDoesNotExist
from tests.utils import get_content_b64

files_dir = os.path.join(os.path.dirname(__file__), 'files')


class MRootStoreTestCase(TestCase):
    def test_get_cert_by_subject(self):
        res = URootStore().get_cert_by_subject(subject='CryptoPro GOST Root CA')
        self.assertEqual(
            res.subject.data,
            {
                'OGRN': '1037700085444',
                'INN': '007717107991',
                'C': 'RU',
                'S': 'Moscow',
                'L': 'Moscow',
                'O': '"LLC ""Crypto-Pro"""',
                'CN': 'CryptoPro GOST Root CA',
            }
        )
        self.assertEqual(
            res.issuer.data,
            {
                'OGRN': '1037700085444',
                'INN': '007717107991',
                'C': 'RU',
                'S': 'Moscow',
                'L': 'Moscow',
                'O': '"LLC ""Crypto-Pro"""',
                'CN': 'CryptoPro GOST Root CA',
            }
        )
        self.assertEqual(res.valid_from, datetime(2018, 11, 15, 14, 14, 9))
        self.assertEqual(res.valid_to, datetime(2033, 11, 15, 14, 14, 9))
        self.assertEqual(res.thumbprint, '34E21FC04D3576B0ADA81FD081955E2778291CC5')
        self.assertEqual(res.alt_name, None)

    def test_get_cert_by_thumbprint(self):
        res = URootStore().get_cert_by_thumbprint(thumbprint='34e21fc04d3576b0ada81fd081955e2778291cc5')
        self.assertEqual(res.thumbprint, '34E21FC04D3576B0ADA81FD081955E2778291CC5')


class UMyStoreTestCase(TestCase):
    def test_install_and_delete_certificate(self):
        thumbprint = '9e78a331020e528c046ffd57704a21b7d2241cb3'

        with self.assertRaises(CertDoesNotExist) as context:
            UMyStore().get_cert_by_thumbprint(thumbprint)
        self.assertTrue('Could not find the desired certificate.' in str(context.exception))

        cert_str = get_content_b64(os.path.join(files_dir, 'certs', 'uc_1_is_guc.cer'))
        res = UMyStore().install_certificate(cert_str.decode('utf-8'))
        self.assertEqual(
            res.subject.data,
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
        cert = UMyStore().get_cert_by_thumbprint(thumbprint)
        self.assertIsNotNone(cert)
        UMyStore().delete_certificate(thumbprint)

        with self.assertRaises(CertDoesNotExist) as context:
            UMyStore().get_cert_by_thumbprint(thumbprint)
        self.assertTrue('Could not find the desired certificate.' in str(context.exception))

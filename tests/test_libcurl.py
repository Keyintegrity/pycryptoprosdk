import unittest
from pycryptoprosdk.libcurl import Curl


class TestLibCurl(unittest.TestCase):
    def setUp(self):
        self.curl = Curl()
        self.url = 'http://127.0.0.1:8000/test/'

    def test_curl_get(self):
        res = self.curl.get(self.url, headers={'HEADER1': 'header 1', 'HEADER2': 'header 2'})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.text, '1')

    def test_curl_post(self):
        data = {
            'field1': 'value1',
            'field2': 'value2',
        }

        res = self.curl.post(url=self.url, data=data, headers={'HEADER1': 'header 1', 'HEADER2': 'header 2'})

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.text, '1')

    def test_curl_post_with_files(self):
        data = {
            'field1': 'value1',
            'field2': 'value2',
        }

        files = {
            'file1': ('test.png', b'content'),
        }

        res = self.curl.post(url=self.url, data=data, files=files)

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.text, '1')

    def test_curl_post_with_content_type(self):
        data = {
            'field1': 'value1',
            'field2': 'value2',
        }

        files = {
            'file1': ('test.png', b'content', 'image/png'),
        }

        res = self.curl.post(url=self.url, data=data, files=files)

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.text, '1')

    def test_force_multipart(self):
        data = {'field1': 'value1'}

        res = self.curl.post(url=self.url, data=data, force_multipart=True)

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.text, '1')

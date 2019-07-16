import unittest
from pycryptoprosdk.libcurl import Curl


class TestLibCurl(unittest.TestCase):
    def setUp(self):
        self.curl = Curl()
        self.url = 'http://127.0.0.1:8000/test/'

    def test_curl_get(self):
        res = self.curl.get(self.url)
        print(res.status_code)
        print(res.text)

    def test_curl_post(self):
        data = {
            'field1': 'value1',
            'field2': 'value2',
        }

        with open('/home/uishnik/img.png', 'rb') as f:
            c = f.read()

        files = {
            'file1': ('test.png', c, 'image/jpeg'),
        }

        res = self.curl.post(url=self.url, data=data, files=files, verbose=False)
        print(res.status_code)
        print(res.text)

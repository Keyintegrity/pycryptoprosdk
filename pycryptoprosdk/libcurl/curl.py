from urllib.parse import urlencode
from pycryptoprosdk import libcpcurl
from . import exceptions


class Curl:
    def get(self, url, verbose=False):
        """
        from pycryptoprosdk.libcurl import Curl
        curl = Curl()
        res = curl.get('http://example.com/test/')
        print(res.status_code)
        print(res.text)
        """
        res = libcpcurl.curl_get(url, verbose)
        return Response(res)

    def post(self, url, data=None, files=None, force_multipart=False, verbose=False):
        """
        from pycryptoprosdk.libcurl import Curl
        curl = Curl()
        res = curl.post(
            url='http://example.com/test/',
            data={
                'field1': 'value1',
                'field2': 'value2',
            },
            files={
                'file1': ('foo.txt', b'foo content'),
                'file2': ('bar.txt', b'bar content'),
            }
        )
        print(res.status_code)
        print(res.text)
        """
        data = self._prepare_data(data, is_multipart=files or force_multipart)

        if files:
            files = self._prepare_files(files)

        res = libcpcurl.curl_post(url, data, files, verbose)

        return Response(res)

    def _encode(self, v):
        if isinstance(v, str):
            return v.encode('utf-8')
        return v

    def _prepare_data(self, data, is_multipart):
        if data is None:
            return b''

        if is_multipart:
            return [
                [
                    self._encode(k),
                    self._encode(v),
                ] for k, v in data.items()
            ]
        return urlencode(data).encode('utf-8')

    def _prepare_files(self, files):
        return [
            [
                self._encode(k),
                self._encode(v[0]),
                self._encode(v[1]),
                self._encode(v[2]),
            ] for k, v in files.items()
        ]


class Response:
    def __init__(self, res):
        self._check_perform_code(res['perform_code'])
        self.status_code = res['status_code']
        self.text = res['content']

    def _check_perform_code(self, perform_code):
        if perform_code == 0:
            return

        if perform_code == 6:
            raise exceptions.CouldntResolve('Couldn\'t resolve host.')

        if perform_code == 7:
            raise exceptions.CouldntConnect('Failed to connect to host or proxy.')

        raise exceptions.CurlException('Failed to perform request. Error {}'.format(perform_code))

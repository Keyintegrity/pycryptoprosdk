from urllib.parse import urlencode

from pycryptoprosdk import libcpcurl
from . import exceptions


class Curl:
    def get(self, url, headers=None, verbose=False):
        """
        from pycryptoprosdk.libcurl import Curl
        curl = Curl()
        res = curl.get('http://example.com/test/')
        print(res.status_code)
        print(res.text)
        """
        return self._request(method='get', url=url, headers=headers, verbose=verbose)

    def post(self, url, data=None, files=None, headers=None, force_multipart=False, verbose=False):
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
        return self._request('post', url, data, files, headers, force_multipart, verbose)

    def _request(self, method, url, data=None, files=None, headers=None, force_multipart=False, verbose=False):
        method = method.upper()

        data = self._prepare_data(data, is_multipart=files or force_multipart)

        if files:
            files = self._prepare_files(files)

        if headers:
            headers = self._prepare_headers(headers)

        res = libcpcurl.request(method, url, data, files, headers, verbose)

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
        res = []

        for filename, values in files.items():
            l = [
                self._encode(filename),
                self._encode(values[0]),
                self._encode(values[1]),
            ]
            if len(values) == 3:
                l.append(self._encode(values[2]))

            res.append(l)

        return res

    def _prepare_headers(self, headers):
        return [
            [
                self._encode(k),
                self._encode(v),
            ] for k, v in headers.items()
        ]


class Response:
    def __init__(self, res):
        self._res = res
        self._check_perform_code()
        self.status_code = res['status_code']
        self.text = res['content']

    def _check_perform_code(self):
        perform_code = self._res['perform_code']

        if perform_code == 0:
            return

        if perform_code == 6:
            raise exceptions.CouldntResolve('Couldn\'t resolve host.')

        if perform_code == 7:
            raise exceptions.CouldntConnect('Failed to connect to host or proxy.')

        raise exceptions.CurlException('Failed to perform request. Error {}'.format(perform_code))

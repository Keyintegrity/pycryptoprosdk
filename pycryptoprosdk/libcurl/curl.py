import ctypes
import os
from urllib.parse import urlencode

from pycryptoprosdk.libcurl import const
from pycryptoprosdk.libcurl.exceptions import (
    CurlException,
    CouldntConnect,
    CouldntResolve,
)


write_function_wrap = ctypes.CFUNCTYPE(
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_char_p)
)


lib = ctypes.CDLL(os.environ.get('LIBCURL') or '/opt/cprocsp/lib/amd64/libcpcurl.so')


def write_function(cont, size, nmemb, userp):
    out = ctypes.string_at(cont, size * nmemb)
    userp[0] = out
    return size * nmemb


class Response:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class CurlForm:
    def __init__(self):
        self._curl_formadd = lib.curl_formadd
        self._curl_formfree = lib.curl_formfree
        self.post = ctypes.pointer(const.CurlHttpPost())
        self.last = const.CurlHttpPost()

    def add_field(self, name, value):
        self._curl_formadd(
            ctypes.byref(self.post),
            ctypes.byref(self.last),
            const.CURLFORM_COPYNAME, name.encode('utf-8'),
            const.CURLFORM_COPYCONTENTS, value.encode('utf-8'),
            const.CURLFORM_END
        )

    def add_file_field(self, field_name, file):
        if type(file) is str:
            self._curl_formadd(
                ctypes.byref(self.post),
                ctypes.byref(self.last),
                const.CURLFORM_COPYNAME, field_name.encode('utf-8'),
                const.CURLFORM_FILE, file.encode('utf-8'),
                const.CURLFORM_END
            )
            return

        if type(file) is tuple:
            file_name, file_data = file
            length = len(file_data)

            self._curl_formadd(
                ctypes.byref(self.post),
                ctypes.byref(self.last),
                const.CURLFORM_COPYNAME, field_name.encode('utf-8'),
                const.CURLFORM_BUFFER, file_name.encode('utf-8'),
                const.CURLFORM_BUFFERPTR, ctypes.c_char_p(file_data),
                const.CURLFORM_BUFFERLENGTH, ctypes.c_long(length),
                const.CURLFORM_END
            )
            return

        raise ValueError("'file' variable must be 'str' or 'tuple', not '{}'".format(type(file)))

    def free(self):
        self._curl_formfree(self.post)


class Curl:
    def __init__(self):
        self._curl_easy_init = lib.curl_easy_init
        self._curl_easy_init.restype = ctypes.POINTER(ctypes.c_void_p)

        self._curl_easy_setopt = lib.curl_easy_setopt
        self._curl_easy_perform = lib.curl_easy_perform
        self._curl_easy_getinfo = lib.curl_easy_getinfo
        self._curl_easy_cleanup = lib.curl_easy_cleanup

        self._curl_easy_strerror = lib.curl_easy_strerror
        self._curl_easy_strerror.restype = ctypes.c_char_p

        self._curl = self._curl_easy_init()
        if not self._curl:
            raise CurlException('Failed to initialize curl')

    def get(self, url):
        """
        from pycryptoprosdk.libcurl import Curl

        curl = Curl()
        res = curl.get('http://example.com/test/')

        print(res.status_code)
        print(res.text)

        curl.cleanup()
        """
        self._set_opt(const.CURLOPT_URL, url.encode('utf-8'))

        s = ctypes.c_char_p()
        self._set_opt(const.CURLOPT_WRITEFUNCTION, write_function_wrap(write_function))
        self._set_opt(const.CURLOPT_WRITEDATA, ctypes.byref(s))

        self._perform()
        res = self._get_response(s.value)

        return res

    def post(self, url, data, files=None, force_multipart=False):
        """
        from pycryptoprosdk.libcurl import Curl

        curl = Curl()
        res = curl.post(
            url='http://example.com/test/',
            data={
                'login': '1024494001',
                'password': 'd8Z7rHL8',
                'refId': '4db0c3d7-96f3-4ca1-b4c3-88eaeeb52b13',
            },
            files={
                'file': '/opt/project/tests/files/img.png',
                'file1': ('test.txt', b'content'),
            }
        )

        print(res.status_code)
        print(res.text)

        curl.cleanup()
        """
        form = None

        self._set_opt(const.CURLOPT_URL, url.encode('utf-8'))

        if files or force_multipart:
            form = self._get_form(data, files)
            self._set_opt(const.CURLOPT_HTTPPOST, form.post)
        else:
            query_string = urlencode(data)
            self._set_opt(const.CURLOPT_POSTFIELDS, query_string.encode('utf-8'))

        s = ctypes.c_char_p()
        self._set_opt(const.CURLOPT_WRITEFUNCTION, write_function_wrap(write_function))
        self._set_opt(const.CURLOPT_WRITEDATA, ctypes.byref(s))

        self._perform()

        if form:
            form.free()

        res = self._get_response(s.value)

        return res

    def cleanup(self):
        self._curl_easy_cleanup(self._curl)

    def _set_opt(self, opt, value):
        setopt_res = self._curl_easy_setopt(self._curl, opt, value)
        if setopt_res != 0:
            raise CurlException('Failed to set option: {}. Error code: {}'.format(
                self._curl_easy_strerror(setopt_res).decode('utf-8'),
                setopt_res
            ))

    def _get_form(self, data, files):
        form = CurlForm()
        for field_name, value in data.items():
            form.add_field(field_name, value)

        if files:
            for field_name, file in files.items():
                if type(file) not in (str, tuple):
                    raise ValueError("files item must be 'str' or 'tuple', not '{}'".format(type(files)))

                form.add_file_field(field_name, file)

        return form

    def _perform(self):
        perform_res = self._curl_easy_perform(self._curl)
        if perform_res != 0:
            if perform_res == 6:
                raise CouldntResolve('Couldn\'t resolve host.')

            if perform_res == 7:
                raise CouldntConnect('Failed to connect to host or proxy.')

            raise CurlException('Failed to perform request. Error {}'.format(perform_res))

    def _get_response(self, content):
        status_code = ctypes.c_long()
        getinfo_res = self._curl_easy_getinfo(self._curl, const.CURLINFO_RESPONSE_CODE, ctypes.byref(status_code))
        if getinfo_res != 0:
            raise CurlException('Failed to get CURLINFO_RESPONSE_CODE. Error {}'.format(getinfo_res))

        return Response(
            status_code=status_code.value,
            text=content
        )

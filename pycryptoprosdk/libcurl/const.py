import ctypes


CURLE_OK = 0

CURLOPT_WRITEDATA = 10001
CURLOPT_URL = 10002
CURLOPT_POSTFIELDS = 10015
CURLOPT_HTTPPOST = 10024
CURLOPT_WRITEFUNCTION = 20011

CURLFORM_COPYNAME = 1
CURLFORM_COPYCONTENTS = 4
CURLFORM_FILECONTENT = 7
CURLFORM_FILE = 10
CURLFORM_BUFFER = 11
CURLFORM_BUFFERPTR = 12
CURLFORM_BUFFERLENGTH = 13
CURLFORM_END = 17

CURLINFO_RESPONSE_CODE = 0x00200002


class CurlSlist(ctypes.Structure):
    pass


CurlSlist._fields_ = [
    ('data', ctypes.c_char_p),
    ('next', ctypes.POINTER(CurlSlist)),
]


class CurlHttpPost(ctypes.Structure):
    pass


CurlHttpPost._fields_ = [
    ('next', ctypes.POINTER(CurlHttpPost)),
    ('name', ctypes.c_char_p),
    ('namelength', ctypes.c_long),
    ('contents', ctypes.c_char_p),
    ('contentslength', ctypes.c_long),
    ('buffer', ctypes.c_char_p),
    ('bufferlength', ctypes.c_long),
    ('contenttype', ctypes.c_char_p),
    ('contentheader', ctypes.POINTER(CurlSlist)),
    ('more', ctypes.POINTER(CurlHttpPost)),
    ('flags', ctypes.c_long),
    ('showfilename', ctypes.c_char_p),
    ('userp', ctypes.c_void_p),
]

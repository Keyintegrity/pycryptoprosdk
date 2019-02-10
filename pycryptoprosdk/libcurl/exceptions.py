class CurlException(Exception):
    pass


class CouldntConnect(CurlException):
    pass


class CouldntResolve(CurlException):
    pass

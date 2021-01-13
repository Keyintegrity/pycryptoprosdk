from distutils.core import setup, Extension
from distutils.util import get_platform
from os import path


d = path.abspath(path.dirname(__file__))
with open(path.join(d, 'README.rst')) as f:
    long_description = f.read()


libpycades = Extension(
    name='pycryptoprosdk.libpycades',
    sources=[
        'pycryptoprosdk/libpycades.cpp',
    ],
    include_dirs=[
        '/opt/cprocsp/include',
        '/opt/cprocsp/include/cpcsp',
        '/opt/cprocsp/include/pki',
    ],
    define_macros=[
        ('UNIX', '1'),
        ('HAVE_LIMITS_H', '1'),
        ('HAVE_STDINT_H', '1'),
        ('SIZEOF_VOID_P', '8'),
    ],
    language='c++',
    extra_link_args=[
        '-L/opt/cprocsp/lib/amd64',
        '-lcapi20',
        '-lcapi10',
        '-lcades',
        '-lrdrsup',
    ]
)

if get_platform().startswith("macos"):
    libpycades.extra_link_args=[
        '-L/opt/cprocsp/lib/',
        '-lcapi20',
        '-lcapi10',
        '-lrdrsup',
        '-L/Applications/CryptoPro_ECP.app/Contents/MacOS/lib/',
        '-lcades',
        '-Wl,-rpath,/Applications/CryptoPro_ECP.app/Contents/MacOS/lib/',
    ]

setup(
    name='pycryptoprosdk',
    version='1.0.0',
    url='https://github.com/Keyintegrity/pycryptoprosdk',
    author='uishnik',
    author_email='uishnik@yandex.ru',
    long_description=long_description,
    packages=[
        'pycryptoprosdk',
    ],
    ext_modules=[
        libpycades,
    ]
)

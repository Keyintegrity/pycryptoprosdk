from distutils.core import setup, Extension
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


setup(
    name='pycryptoprosdk',
    version='1.0.0-rc1',
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

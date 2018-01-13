from distutils.core import setup, Extension


libpycades = Extension(
    'pycryptoprosdk.libpycades',
    sources=['pycryptoprosdk/libpycades.cpp'],
    include_dirs=[
        '/opt/cprocsp/include',
        '/opt/cprocsp/include/cpcsp',
        '/opt/cprocsp/include/pki',
    ],
    define_macros=[
        ('UNIX', '1'),
        ('HAVE_LIMITS_H', '1'),
        ('HAVE_STDINT_H', '1'),
        ('SIZEOF_VOID_P', '8')
    ],
    language='c++',
    extra_link_args=['-L/opt/cprocsp/lib/amd64', '-lcapi20', '-lcapi10', '-lcades', '-lrdrsup']
)


setup(
    name='pycryptoprosdk',
    version='0.0.2',
    packages=['pycryptoprosdk'],
    ext_modules=[
        libpycades
    ]
)

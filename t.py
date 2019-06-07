import os
from base64 import b64encode
from pycryptoprosdk import libpycades


files_dir = os.path.join(os.path.dirname(__file__), 'tests', 'files')


# with open(os.path.join(files_dir, 'signatures', 'doc.txt'), 'rb') as f:
#     content = f.read()
#
# h = libpycades.create_hash(content, 'CALG_GR3411')
# print(h)

# cert_data = libpycades.get_cert_by_subject('ROOT', 'CRYPTO-PRO Test Center 2')
# print(cert_data)

# with open(os.path.join('tests', 'files', 'signatures', 'test_alt_name.txt.sig')) as f:
#     cert_data = libpycades.get_signer_cert_from_signature(f.read())
# print(cert_data)

# print(libpycades.get_cert_by_thumbprint('MY', 'bb53a52aa36682839f06cccc3e1cac827ee1e25f'))

# with open(os.path.join(files_dir, 'certs', 'uc_1_is_guc.cer'), 'rb') as f:
#     cert_data = b64encode(f.read())
# print(libpycades.install_certificate('MY', cert_data.decode('utf-8')))

# libpycades.delete_certificate('MY', '9e78a331020e528c046ffd57704a21b7d2241cb3')

with open(os.path.join('tests', 'files', 'signatures', 'doc.txt'), 'rb') as f:
    content = b64encode(f.read())

with open(os.path.join('tests', 'files', 'signatures', 'doc.txt.sgn')) as f:
    signature = f.read()

res = libpycades.verify_detached(content.decode('utf-8'), signature)
print(res)

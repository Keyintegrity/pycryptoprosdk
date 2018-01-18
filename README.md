# pycryptoprosdk
Библиотека для работы с Cryptopro CSP в python

## Установка
1. Установить КриптоПро CSP.
2. Установить пакеты lsb-cprocsp-devel-.noarch.rpm и cprocsp-pki-amd64-cades.rpm из состава КриптоПро ЭЦП SDK.
3. При необходимости, создать симлинк:
```
ln -s /opt/cprocsp/lib/amd64/libcades.so.2.0.0 /opt/cprocsp/lib/amd64/libcades.so
```
Пример установки пакетов можно посмотреть в [pycryptoprosdk/compose/Dockerfile](https://github.com/Keyintegrity/pycryptoprosdk/blob/master/compose/Dockerfile).

4. Установить pycryptoprosdk:
```
python setup.py install
```

## Примеры использования
```python
from pycryptoprosdk import CryptoProSDK


sdk = CryptoProSDK()


# верификация отсоединенной подписи:
with open('doc.txt', 'rb') as f:
    content = b64encode(f.read())

with open('doc.txt.sig', 'rb') as f:
    signature = b64encode(f.read())

res = sdk.verify_detached(content, signature)


# создание хэша файла по ГОСТу:
with open('doc.txt'), 'rb') as f:
    content = f.read()
h = sdk.create_hash(content)


# поиск сертификата в хранилище MY по отпечатку:
cert = sdk.get_cert_by_thumbprint('MY', '046255290b0eb1cdd1797d9ab8c81f699e3687f3')


# поиск сертификата по имени:
cert = sdk.get_cert_by_subject('MY', 'CRYPTO-PRO Test Center 2')


# установка сертификата в хранилище MY:
with open('certificate.cer'), 'rb') as f:
    cert_content = f.read()
sdk.install_certificate('MY', b64encode(cert_str))


# удаление сертификата из хранилища MY по отпечатку:
sdk.delete_certificate('MY', '9e78a331020e528c046ffd57704a21b7d2241cb3')


# извлечение сертификата подписанта из подписи:
with open('signature.sig', 'rb') as f:
    signature_content = f.read()
cert = sdk.get_signer_cert_from_signature(signature_content)
```

Сборка образа и запуск тестов:

```
docker-compose build
```

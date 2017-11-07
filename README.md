# pycryptoprosdk
Библиотека для работы с Cryptopro CSP в python

## Установка
1. Установить КриптоПро CSP.
2. Установить пакеты lsb-cprocsp-devel-.noarch.rpm и cprocsp-pki-amd64-cades.rpm из состава КриптоПро ЭЦП SDK.
3. При необходимости, создать симлинк:
```
ln -s /opt/cprocsp/lib/amd64/libcades.so.2.0.0 /opt/cprocsp/lib/amd64/libcades.so
```
4. Установить pycryptoprosdk:
```
python setup.py install
```

## Примеры использования
```python
from pycryptoprosdk import CryptoProSDK


# верификация отсоединенной подписи

with open('doc.txt', 'rb') as f:
    content = b64encode(f.read())

with open('doc.txt.sig', 'rb') as f:
    signature = f.read()

res = self.sdk.verify_detached(content, signature)
```

Сборка образа и запуск тестов:

```
docker-compose build
```

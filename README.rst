pycryptoprosdk
==============
Библиотека для работы с Cryptopro CSP в python

Установка
---------
* Установить КриптоПро CSP.
* Установить пакеты lsb-cprocsp-devel-.noarch.rpm и cprocsp-pki-amd64-cades.rpm из состава КриптоПро ЭЦП SDK.
* При необходимости, создать симлинк:

.. code-block:: shell

    ln -s /opt/cprocsp/lib/amd64/libcades.so.2.0.0 /opt/cprocsp/lib/amd64/libcades.so

Пример установки пакетов можно посмотреть в `pycryptoprosdk/compose/Dockerfile <https://github.com/Keyintegrity/pycryptoprosdk/blob/master/compose/Dockerfile>`_.

* Установить pycryptoprosdk:

.. code-block:: shell

    pip install pycryptoprosdk

Примеры использования
---------------------
.. code-block:: python

    from pycryptoprosdk import CryptoProSDK


    sdk = CryptoProSDK()


    # верификация отсоединенной подписи:
    with open('doc.txt', 'rb') as f:
        content = b64encode(f.read())

    with open('doc.txt.sig', 'rb') as f:
        signature = b64encode(f.read())

    res = sdk.verify_detached(content, signature)


    # создание хэша файла алгоритмом ГОСТ Р 34.11-94:
    with open('doc.txt'), 'rb') as f:
        content = f.read()
    h = sdk.create_hash(content, alg='CALG_GR3411')


    # поиск сертификата в хранилище MY по отпечатку:
    cert = sdk.get_cert_by_thumbprint('MY', '046255290b0eb1cdd1797d9ab8c81f699e3687f3')


    # поиск сертификата по имени:
    cert = sdk.get_cert_by_subject('MY', 'CRYPTO-PRO Test Center 2')


    # установка сертификата в хранилище MY:
    with open('certificate.cer'), 'rb') as f:
        cert_content = f.read()
    sdk.install_certificate('MY', b64encode(cert_content))


    # удаление сертификата из хранилища MY по отпечатку:
    sdk.delete_certificate('MY', '9e78a331020e528c046ffd57704a21b7d2241cb3')


    # извлечение сертификата подписанта из подписи:
    with open('signature.sig', 'rb') as f:
        signature_content = f.read()
    cert = sdk.get_signer_cert_from_signature(signature_content)


Сборка образа и запуск тестов
-----------------------------
.. code-block:: shell

    docker-compose up --build --force-recreate

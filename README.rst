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

    >>> from pycryptoprosdk import CryptoProSDK


    >>> sdk = CryptoProSDK()


    # Создание и проверка отсоединенной подписи:
    >>> content = 'test content'
    >>> cert = sdk.get_cert_by_subject('MY', 'Ivan')
    >>> signature = sdk.sign(content, cert.thumbprint, 'MY', detached=True)
    >>> result = sdk.verify_detached(content, signature)

    # статус проверки:
    >>> result.verification_status
    0

    # 0: Успешная проверка подписи.
    # 1: Отсутствуют или имеют неправильный формат атрибуты со ссылками и значениями доказательств подлинности.
    # 2: Сертификат, на ключе которого было подписано сообщение, не найден.
    # 3: В сообщении не найден действительный штамп времени на подпись.
    # 4: Значения ссылок на доказательства подлинности и сами доказательства, вложенные в сообщение, не соответствуют друг другу.
    # 5: Не удалось построить цепочку для сертификата, на ключе которого подписано сообщение.
    # 6: Ошибка проверки конечного сертификата на отзыв.
    # 7: Ошибка проверки сертификата цепочки на отзыв.
    # 8: Сообщение содержит неверную подпись.
    # 9: В сообщении не найден действительный штамп времени на доказательства подлинности подписи.
    # 10: Значение подписанного атрибута content-type не совпадает со значением, указанным в поле encapContentInfo.eContentType.

    # сертификат подписанта:
    >>> result.cert.as_dict()
    {'CN': 'Ivan'}


    # создание хэша файла алгоритмом ГОСТ Р 34.11-94:
    >>> sdk.create_hash('some text', alg='CALG_GR3411')
    '046255290b0eb1cdd1797d9ab8c81f699e3687f3'


    # поиск сертификата в хранилище MY по отпечатку:
    >>> cert = sdk.get_cert_by_thumbprint('MY', '046255290b0eb1cdd1797d9ab8c81f699e3687f3')


    # поиск сертификата по имени:
    >>> cert = sdk.get_cert_by_subject('MY', 'CRYPTO-PRO Test Center 2')


    # установка сертификата в хранилище MY:
    >>> with open('certificate.cer'), 'rb') as f:
    >>>     cert_content = f.read()
    >>> sdk.install_certificate('MY', cert_content)


    # удаление сертификата из хранилища MY по отпечатку:
    >>> sdk.delete_certificate('MY', '9e78a331020e528c046ffd57704a21b7d2241cb3')


    # извлечение сертификата подписанта из подписи:
    >>> with open('signature.sig', 'rb') as f:
    >>>     signature_content = f.read()
    >>> cert = sdk.get_signer_cert_from_signature(signature_content)

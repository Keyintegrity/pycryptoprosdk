# Возможные значения атрибута verificationStatus:
CADES_VERIFY_SUCCESS = 0  # Успешная проверка подписи.
CADES_VERIFY_INVALID_REFS_AND_VALUES = 1  # Отсутствуют или имеют неправильный формат атрибуты со ссылками и значениями доказательств подлинности.
CADES_VERIFY_SIGNER_NOT_FOUND = 2  # Сертификат, на ключе которого было подписано сообщение, не найден.
CADES_VERIFY_NO_VALID_SIGNATURE_TIMESTAMP = 3  # В сообщении не найден действительный штамп времени на подпись.
CADES_VERIFY_REFS_AND_VALUES_NO_MATCH = 4  # Значения ссылок на доказательства подлинности и сами доказательства, вложенные в сообщение, не соответствуют друг другу.
CADES_VERIFY_NO_CHAIN = 5  # Не удалось построить цепочку для сертификата, на ключе которого подписано сообщение.
CADES_VERIFY_END_CERT_REVOCATION = 6  # Ошибка проверки конечного сертификата на отзыв.
CADES_VERIFY_CHAIN_CERT_REVOCATION = 7  # Ошибка проверки сертификата цепочки на отзыв.
CADES_VERIFY_BAD_SIGNATURE = 8  # Сообщение содержит неверную подпись.
CADES_VERIFY_NO_VALID_CADES_C_TIMESTAMP = 9  # В сообщении не найден действительный штамп времени на доказательства подлинности подписи.
CADES_VERIFY_ECONTENTTYPE_NO_MATCH = 10  # Значение подписанного атрибута content-type не совпадает со значением, указанным в поле encapContentInfo.eContentType.


# возможные значения атрибута error:
CRYPT_E_INVALID_MSG_TYPE = '0x80091004'  # The cryptographic message type is not valid.
CRYPT_E_UNEXPECTED_MSG_TYPE = '0x8009200a'  # Not a signed cryptographic message.
CRYPT_E_NO_SIGNER = '0x8009200e'  # The message does not have any signers or a signer for the specified dwSignerIndex.
E_INVALIDARG = '0x80070057'  # Invalid message and certificate encoding types. Currently only PKCS_7_ASN_ENCODING and X509_ASN_ENCODING_TYPE are supported.
NTE_BAD_ALGID = '0x80090008'  # The message was hashed and signed by using an unknown or unsupported algorithm.
NTE_BAD_SIGNATURE = '0x80090006'  # The message's signature was not verified.

# больше кодов: https://msdn.microsoft.com/en-us/library/windows/desktop/dd542646(v=vs.85).aspx

#!/usr/bin/env bash

set -e

renew_signature(){
    rdn=$1
    file_name=$2
    dir_name=./tests/files/signatures

    /opt/cprocsp/bin/amd64/cryptcp -creatcert \
        -rdn "$rdn" \
        -cont '\\.\HDIMAGE\cont1' \
        -sg -ku -du -ca http://cryptopro.ru/certsrv

    /opt/cprocsp/bin/amd64/cryptcp -signf \
        -dir ${dir_name} \
        -dn "Иванов Иван Иванович" \
        -cert \
        ${dir_name}/${file_name}
}

# обновление тестовой подписи
renew_signature 'CN=Иванов Иван Иванович,INN=123456789047,OGRN=1123300000053,SNILS=12345678901,STREET="Улица, дом",L=Город' 'doc.txt'

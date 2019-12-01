#!/usr/bin/env bash

cn=pycryptoprosdk

install_cert(){
    rdn=$1
    uuid=$(uuidgen)

    /opt/cprocsp/bin/amd64/certmgr -delete -store umy -dn CN=${cn}

    /opt/cprocsp/bin/amd64/cryptcp -creatcert \
        -rdn "$rdn" \
        -cont '\\.\HDIMAGE\cont'${uuid} \
        -sg -ku -du -ca http://cryptopro.ru/certsrv
}

install_cert "CN=${cn},INN=123456789047,OGRN=1123300000053,SNILS=12345678901,STREET=\"Улица, дом\",L=Город"

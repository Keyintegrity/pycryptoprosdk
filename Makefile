build-ext:
	rm -rf ./build \
		&& rm -f ./pycryptoprosdk/libpycades.cpython-* \
		&& python ./setup.py build_ext --inplace

delete-test-cert:
	/opt/cprocsp/bin/amd64/certmgr \
		-delete \
		-store umy \
		-dn CN=pycryptopro

install-test-cert:
	/opt/cprocsp/bin/amd64/cryptcp -creatcert \
		-provtype 80 \
        -provname 'Crypto-Pro GOST R 34.10-2012 KC1 CSP' \
        -rdn 'CN=pycryptoprosdk,INN=123456789047,OGRN=1123300000053,SNILS=12345678901,STREET="Улица, дом",L=Город' \
        -cont '\\.\HDIMAGE\cont'$$(uuidgen) \
        -sg -ku -du -ca http://cryptopro.ru/certsrv

test:
	python -m unittest

docker-image:
	docker build -f ./docker/Dockerfile -t pycryptoprosdk .

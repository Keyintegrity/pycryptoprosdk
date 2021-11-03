FROM python:3.5

ENV PYTHONUNBUFFERED 1
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    g++ \
    lsb-base alien lsb-core \
    mc \
    nano \
    python-pip \
    python-mysqldb

COPY ./compose/cpcsp /cpcsp
RUN bash /cpcsp/install.sh

RUN cd /cpcsp && alien -kci lsb-cprocsp-devel-4.0.0-4.noarch.rpm cprocsp-pki-2.0.0-amd64-cades.rpm
RUN ln -s /opt/cprocsp/lib/amd64/libcades.so.2.0.0 /opt/cprocsp/lib/amd64/libcades.so

COPY ./compose/certs /certs
RUN /opt/cprocsp/bin/amd64/certmgr -inst -store uroot -f /certs/cert_cryptopro_test.cer \
    && /opt/cprocsp/bin/amd64/certmgr -inst -store uroot -f /certs/guc.cer \
    && /opt/cprocsp/sbin/amd64/cpconfig -ini '\config\Parameters' -add bool Rfc6125_NotStrict_ServerName_Check true

COPY ./requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

COPY ./ /build/pycryptoprosdk
WORKDIR /build/pycryptoprosdk

#RUN cd /build/pycryptoprosdk && python setup.py install

ENV TERM xterm
ENV TZ=Europe/Moscow

COPY ./compose/docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]

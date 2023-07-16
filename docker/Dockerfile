FROM python:3.10

ENV PYTHONUNBUFFERED 1
ENV DEBIAN_FRONTEND noninteractive

RUN apt update && \
    apt install -y --no-install-recommends \
    alien \
    g++ \
    mc \
    nano

COPY ./docker/cpcsp /cpcsp
COPY ./docker/cades_linux_amd64 /cpcsp
RUN bash /cpcsp/install.sh

RUN cd /cpcsp && alien -kci lsb-cprocsp-devel-5.0.11438-4.noarch.rpm cprocsp-pki-2.0.0-amd64-cades.rpm
RUN ln -s /opt/cprocsp/lib/amd64/libcades.so.2.0.0 /opt/cprocsp/lib/amd64/libcades.so

RUN /opt/cprocsp/sbin/amd64/cpconfig -ini '\config\Parameters' -add bool Rfc6125_NotStrict_ServerName_Check true

COPY ./ /build/pycryptoprosdk
WORKDIR /build/pycryptoprosdk

#RUN cd /build/pycryptoprosdk && python setup.py install

ENV TERM xterm
ENV TZ=Europe/Moscow

COPY ./docker/docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

CMD python ./setup.py build_ext --inplace

CMD make install-test-cert

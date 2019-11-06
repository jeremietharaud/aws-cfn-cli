FROM python:alpine3.8

COPY . /cfncli

RUN \
	cd /cfncli && \
	python setup.py install

WORKDIR /data
ENTRYPOINT ["/usr/local/bin/cfncli"]

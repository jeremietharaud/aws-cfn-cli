FROM python:3.7.9-alpine3.13 as builder

RUN mkdir -p /src
WORKDIR /src

COPY . /src

RUN mkdir -p /install/lib/python3.7/site-packages/

ENV PYTHONPATH ${PYTHONPATH}:/install/lib/python3.7/site-packages

RUN python setup.py install --prefix=/install

FROM gcr.io/distroless/python3

WORKDIR /data

COPY --from=builder /usr/local/lib/python3.7/site-packages /usr/local/lib/python3.7/site-packages
COPY --from=builder /install /usr/local

ENV PYTHONPATH /usr/local/lib/python3.7/site-packages

CMD ["/usr/local/bin/cfncli", "-h"]

ENTRYPOINT ["python", "/usr/local/bin/cfncli"]

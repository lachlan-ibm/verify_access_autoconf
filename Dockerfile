#Container to obsfucate secrets
FROM alpine:latest

RUN apk add --update py3-pip python3

RUN pip3 install verify-access-autoconf

CMD ["/usr/bin/python3", "-m", "verify_access_autoconf"]

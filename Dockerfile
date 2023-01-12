#Container to obsfucate secrets
FROM alpine:latest as intermediate

ARG ART_API_USER

ARG ART_API_KEY

WORKDIR /pip-packages/

RUN apk add --update py3-pip python3

RUN pip3 download --no-deps pyisva verify-access-configurator --extra-index https://$ART_API_USER:$ART_API_KEY@eu.artifactory.swg-devops.com/artifactory/api/pypi/sec-iam-isam-devops-team-pypi-local/simple

#Actual container
FROM alpine:latest

RUN apk add --update py3-pip python3-dev python3 

COPY --from=intermediate /pip-packages/ /pip-packages/

RUN pip3 install --find-links=/pip-packages/ /pip-packages/*

CMD ["/usr/bin/python3", "-m", "verify_access_autoconf"]

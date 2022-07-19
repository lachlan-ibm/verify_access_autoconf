FROM alpine

RUN apk add --no-cache py3-pip python3-dev libffi-dev openssl-dev gcc libc-dev make curl

RUN curl -L "https://github.com/docker/compose/releases/download/1.25.3/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose \
    && chmod +x /usr/local/bin/docker-compose

WORKDIR /user/src/app

env ISVA_CONFIGURATION_AUTOMATION_BASEDIR /user/src/app

COPY . .

RUN pip3 install --no-cache-dir -r requirements.txt

RUN ln -s /usr/bin/python3 /usr/bin/python && ln -s /usr/bin/pip3 /usr/bin/pip

#ENV PYTHONPATH "/user/src/app/pyisam:/user/src/app/src"

CMD ["python", "./src/configure.py"]

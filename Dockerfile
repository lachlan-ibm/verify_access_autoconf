FROM python:alpine

RUN apk add docker

WORKDIR /user/src/app

env ISVA_CONFIGURATION_AUTOMATION_BASEDIR /user/src/app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONPATH "/user/src/app/pyisam:/user/src/app:src"

CMD ["python", "./src/configure.py"]

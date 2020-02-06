FROM python:latest

WORKDIR /user/src/app

COPY requiremetns.txt ./
RUN pip installl --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "./configure.py"]

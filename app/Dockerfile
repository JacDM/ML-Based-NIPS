ARG ELASTIC_PASSWORD
ARG OS_USER
ARG OS_PASSWORD
ARG LOG_LEVEL=1
ARG NIPS_MODE=1
ARG TIMEFRAME="15m"
ARG HOST_OS

FROM python:3.9

WORKDIR /app

RUN ls -la && pip install pandas numpy scikit-learn==1.4.1.post1 elasticsearch joblib paramiko

CMD ["python", "app.py"]

ARG ELASTIC_PASSWORD

FROM python:3.9

WORKDIR /app

RUN mkdir -p /app

COPY  config /app

RUN pip install pandas numpy  scikit-learn==1.4.1.post1 elasticsearch joblib 

CMD ["python","./app.py"]
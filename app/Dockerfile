ARG ELASTIC_PASSWORD

FROM python:3.9

WORKDIR /app

RUN ls -la && pip install pandas numpy scikit-learn==1.4.1.post1 elasticsearch joblib 

CMD ["python", "app.py"]

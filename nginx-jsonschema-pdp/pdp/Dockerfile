FROM python:3.10

RUN pip install PyJWT requests gunicorn flask jsonschema

WORKDIR /app
COPY app.py /app
COPY ./policies /app/policies

ENTRYPOINT ["gunicorn", "-b", "0.0.0.0:8080", "--access-logfile", "-", "app:app"]

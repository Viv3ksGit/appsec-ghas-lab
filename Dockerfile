# Intentionally weak container: EOL base image, runs as root, no pinning by digest.
FROM python:3.11-slim-buster

ADD app/ /app
WORKDIR /app
RUN pip install -r requirements.txt

EXPOSE 5000
CMD ["python", "app.py"]

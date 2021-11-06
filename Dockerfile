FROM python:3.10

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src .
EXPOSE 5000

CMD gunicorn -w 4 -b 0.0.0.0:5000 --access-logfile - 'wsgi_app:app'
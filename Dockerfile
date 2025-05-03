FROM python:3.13.3-alpine3.21

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apk update \ 
    && apk add --no-cache postgresql-dev gcc python3-dev musl-dev libffi-dev \
    && pip install --upgrade pip

RUN apk add --no-cache bash

COPY ./requirements.txt ./

RUN pip install -r requirements.txt

COPY ./ ./

#CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "seclogin.asgi:application"]
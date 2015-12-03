# Base Image
FROM gliderlabs/alpine:3.2

RUN apk add --update \
    build-base \
    cython \
    cython-dev \
    py-pip \
    python \
    python-dev \
  && rm -rf /var/cache/apk/*

WORKDIR /app

COPY . /app
RUN pip install -r /app/requirements.txt

EXPOSE 3000
CMD ["honcho", "start"]


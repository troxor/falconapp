# Base Image
FROM gliderlabs/alpine:3.2

RUN apk add --update \
    bash \
    python \
    python-dev \
    py-pip \
    build-base \
    cython \
    cython-dev \
  && rm -rf /var/cache/apk/*

WORKDIR /app

COPY . /app
RUN pip install -r /app/requirements.txt

EXPOSE 3000
CMD ["honcho", "start"]


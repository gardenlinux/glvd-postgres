ARG base=docker.io/library/postgres:15-bookworm
FROM $base

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postgresql-15-debversion && \
    echo 'CREATE EXTENSION debversion' > /docker-entrypoint-initdb.d/create-extension.sql

RUN mkdir -p /var/lib/postgresql/data/pgdata
ADD create-certificate.sh /docker-entrypoint-initdb.d
ADD postgresql.conf /etc/postgresql/

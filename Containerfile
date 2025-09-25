ARG base=docker.io/library/postgres:17-trixie
FROM $base

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postgresql-17-debversion && \
    echo 'CREATE EXTENSION IF NOT EXISTS debversion WITH SCHEMA public;' > /docker-entrypoint-initdb.d/create-extension.sql

ADD postgresql.conf /etc/postgresql/

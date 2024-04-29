ARG base=docker.io/library/postgres:15-bookworm
ARG container_variant
FROM $base AS base_container

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postgresql-15-debversion && \
    echo 'CREATE EXTENSION debversion' > /docker-entrypoint-initdb.d/create-extension.sql

FROM base_container AS variantsampledata
COPY glvd.sql /docker-entrypoint-initdb.d/glvd.sql
COPY postgresql_notls.conf /etc/postgresql/postgresql.conf
ENV VARIANT=SAMPLEDATA

FROM base_container AS variantnotls
COPY postgresql_notls.conf /etc/postgresql/postgresql.conf
ENV VARIANT=NOTLS

FROM base_container AS variant
COPY create-certificate.sh /docker-entrypoint-initdb.d
COPY postgresql.conf /etc/postgresql/
ENV VARIANT=''

FROM variant${container_variant} AS final
RUN echo "Building variant: ${VARIANT}"

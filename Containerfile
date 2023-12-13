ARG base=docker.io/library/postgres:15-bookworm
FROM $base

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postgresql-15-debversion
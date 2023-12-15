#!/bin/bash

openssl req -newkey rsa:4096 \
            -x509 \
            -sha256 \
            -days 3650 \
            -nodes \
            -out /var/lib/postgresql/data/pgdata/server.crt \
            -keyout /var/lib/postgresql/data/pgdata/server.key \
            -subj "/C=DE/ST=BW/L=Walldorf/O=Security/OU=IT Department/CN=GLVD"

cp /etc/postgresql/postgresql.conf /var/lib/postgresql/data/pgdata/.

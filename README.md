# Garden Linux Vulnerability Database - PostgreSQL

This repository contains the container configuration for the PostgreSQL of `glvd`. The Security Tracker does not use the default PostgreSQL container but a custom one which has some extenions and configuration installed. This container is based on the PostgreSQL contaienr from `docker.io`.

The following extensions and configurations have been adjusted for this PostgreSQL container:

| Name | Type | Description |
|------|------|-------------|
| `debversion` | extension | Debian version numbers, used to version Debian binary and source packages |
| `random_page_cost` | configuration | Sets the planner's estimate of the cost of a non-sequentially-fetched disk page. The default is 4.0. The Garden Linux Security Tracker sets this to `1.1` |

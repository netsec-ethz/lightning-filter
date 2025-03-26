#!/bin/bash

# create docker image
docker build -t lf-monitoring -f monitoring.Dockerfile .

# create docker container
docker create --name lf-monitoring --net=host lf-monitoring

# start docker container
docker start lf-monitoring
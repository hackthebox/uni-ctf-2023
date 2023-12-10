#!/bin/bash
docker rm -f web_gatecrash
docker build -t web_gatecrash . && \
docker run --name=web_gatecrash --rm -p1337:1337 -it web_gatecrash
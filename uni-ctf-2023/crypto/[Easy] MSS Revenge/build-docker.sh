#!/bin/bash
NAME="mss_revenge"
docker rm -f crypto_$NAME
docker build --tag=crypto_$NAME . && \
docker run -p 1337:1337 --rm --name=crypto_$NAME --detach crypto_$NAME

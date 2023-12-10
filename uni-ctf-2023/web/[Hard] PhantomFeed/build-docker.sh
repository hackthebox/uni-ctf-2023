#!/bin/bash
docker rm -f web_phantomfeed
docker build -t web_phantomfeed .
docker run --name=web_phantomfeed --rm -p1337:1337 -it web_phantomfeed
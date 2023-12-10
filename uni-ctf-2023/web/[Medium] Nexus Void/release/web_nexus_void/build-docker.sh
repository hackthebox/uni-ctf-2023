#!/bin/bash
docker rm -f web_nexus_void
docker build --tag=web_nexus_void .
docker run --rm -it -p 1337:80 --name=web_nexus_void web_nexus_void
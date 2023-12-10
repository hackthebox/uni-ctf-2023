#!/bin/sh
docker build --tag=zombiedote .
docker run -it -p 1337:1337 --rm --name=zombiedote zombiedote

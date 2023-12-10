#!/bin/sh
docker build --tag=zombienator .
docker run -it -p 1337:1337 --rm --name=zombienator zombienator
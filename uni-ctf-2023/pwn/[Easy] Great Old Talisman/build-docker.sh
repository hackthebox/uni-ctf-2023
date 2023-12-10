#!/bin/sh
docker build --tag=great_old_talisman .
docker run -it -p 1337:1337 --rm --name=great_old_talisman great_old_talisman
#!/bin/bash
NAME="zombiedote"
PATCHED_NAME=$NAME"_patched"

echo "[*] Re-linking..."
pwninit --no-template --bin $NAME --libc glibc/libc.so.6 --ld glibc/ld-2.34.so
rm $NAME && mv $PATCHED_NAME $NAME

echo "[*] Setting up challenge/ ..."
cp $NAME ../challenge/
cp -r glibc/ ../challenge/

echo "[*] Setting up release/ ..."
mkdir -p challenge/
cp $NAME challenge/
cp -r glibc/ challenge/
zip -r "$NAME.zip" challenge/ build-docker.sh Dockerfile
mv "$NAME.zip" ../release/

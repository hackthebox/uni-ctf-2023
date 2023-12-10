#!/bin/ash

# Change flag name
mv /flag.txt /flag$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 10).txt

# Secure entrypoint
chmod 600 /entrypoint.sh

# Generate RSA Key Pair
openssl genrsa -out /app/private.pem 2048

# Extract the public key
openssl rsa -in /app/private.pem -outform PEM -pubout -out /app/public.pem

# Launch supervisord
/usr/bin/supervisord -c /etc/supervisord.conf

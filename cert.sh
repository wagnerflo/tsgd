#!/bin/zsh

openssl req -newkey rsa:2048 -days 365 -nodes -x509 \
        -subj "/CN=tsgd" \
        -extensions SAN \
        -config <(cat /etc/ssl/openssl.cnf \
                      <(printf "[SAN]\nsubjectAltName='IP:192.168.10.100'")) \
        -keyout cert.key -out cert.crt

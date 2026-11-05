#!/bin/bash
docker build -t alpine-openssh-bypass .
docker run -d -p 2222:22 --name alpine-openssh-bypass alpine-openssh-bypass:latest

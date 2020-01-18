#!/bin/bash

## API-SMTA build
## Docker build Go application

RELEASE=v1.0.0

if [ "$1" = "init" ]
then
echo "Starting make environment..."
docker build -t golang . && \
echo "environment is maked"

else
echo "Starting build go binary...."
docker run -it -v $(pwd)/src:/go/src -v $(pwd)/bin:/go/bin \
 golang go build -o bin/smta-${RELEASE} src/app.go && \
echo "Golang binary successfully build"
fi

#!/bin/bash

if [ "$(gofmt -s -l . | wc -l)" -gt 0 ]; then
gofmt -s -l .
echo "Please format Go code by running: go fmt ./..."
exit 1
fi

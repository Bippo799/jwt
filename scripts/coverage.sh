#!/bin/bash

go test -v -covermode=count -coverprofile=coverage.cov ./...

go tool cover -html coverage.cov
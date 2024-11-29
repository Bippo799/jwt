#!/bin/bash

go test ./... -coverprofile coverage.cov

go tool cover -html coverage.cov
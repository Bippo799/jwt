#!/bin/bash

go install github.com/mfridman/tparse@latest  
go vet ./...
go test -v -race -count=1 -json -cover -covermode=atomic -coverprofile=coverage.txt ./... | tee output.json | tparse -follow -notests || true
tparse -format markdown -file output.json -all > $GITHUB_STEP_SUMMARY

go tool cover -html coverage.txt

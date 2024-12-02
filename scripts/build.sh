#!/bin/bash

go install github.com/mfridman/tparse@latest  
go vet ./...
go test -v -race -count=1 -json -cover ./... | tee output.json | tparse -follow -notests || true
tparse -format markdown -file output.json -all > $GITHUB_STEP_SUMMARY
go build ./...
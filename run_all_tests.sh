#!/bin/bash
export SKIP_INTEGRATION=false
export CI=false
go test -count=1 -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

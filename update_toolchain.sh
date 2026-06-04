#!/bin/bash
go mod edit -go=1.26.4
go mod edit -toolchain=go1.26.4
go mod tidy

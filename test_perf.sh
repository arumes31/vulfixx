#!/bin/bash
go test -bench=BenchmarkDashboardHandler -run=^$ ./internal/web

#!/bin/bash
sed -i 's/defer os.Chdir("cmd\/cve-tracker")/_ = os.Chdir("cmd\/cve-tracker")/g' cmd/cve-tracker/main_test.go
sed -i 's/p.Signal(os.Interrupt)/_ = p.Signal(os.Interrupt)/g' cmd/cve-tracker/main_test.go
sed -i 's/defer os.Chdir("internal\/web")/_ = os.Chdir("internal\/web")/g' internal/web/web_test.go

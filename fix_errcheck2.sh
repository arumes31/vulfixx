#!/bin/bash
sed -i 's/_ = os.Chdir("cmd\/cve-tracker")/defer func() { _ = os.Chdir("cmd\/cve-tracker") }()/g' cmd/cve-tracker/main_test.go
sed -i 's/_ = os.Chdir("internal\/web")/defer func() { _ = os.Chdir("internal\/web") }()/g' internal/web/web_test.go

#!/bin/bash
find .github/workflows -type f -name "*.yml" -exec sed -i 's/1\.26\.3/1.26.4/g' {} +
sed -i 's/1\.26\.3/1.26.4/g' Dockerfile

#!/bin/bash
# Remove duplicate slices imports
for file in internal/models/models.go internal/worker/sync_advisory_rss.go internal/worker/sync_fortiguard.go internal/worker/sync_fortiguard_test.go; do
    sed -i '/"slices"/d' $file
    sed -i 's/"time"/"slices"\n\t"time"/g' $file
done

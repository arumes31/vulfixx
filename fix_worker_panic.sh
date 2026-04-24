#!/bin/bash
sed -i 's/go processEmailChange(ctx)/_ = db.InitRedis()\n\tdefer db.CloseRedis()\n\tgo processEmailChange(ctx)/g' internal/worker/worker_test.go

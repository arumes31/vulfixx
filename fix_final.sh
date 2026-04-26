#!/bin/bash
sed -i "s/DELETE FROM users WHERE email IN ('test@example.com', 'admin_init@example.com')/DELETE FROM users WHERE email IN ('test@example.com', 'admin_init@example.com', 'changed@example.com', 'admin_init2@example.com')/g" internal/auth/auth_test.go

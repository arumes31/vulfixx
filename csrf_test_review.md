# Code Review Request: CSRF Validation Test Coverage

## Changes
- Added `ConstantTimeCompareBranch` sub-test to `TestCSRFProtection` in `internal/web/security_test.go`.
  - This test uses tokens of equal length but different content to ensure the constant-time comparison logic is exercised.
- Added `HeaderPrecedence` sub-test to `TestCSRFProtection` in `internal/web/security_test.go`.
  - This test verifies that the `X-CSRF-Token` header takes precedence over form values.

## Verification
- Ran `GOTOOLCHAIN=go1.26.3 go test -v -run TestCSRFProtection ./internal/web/`
- Verified 100% statement coverage for `ValidateCSRF` in `internal/web/base.go` using `go tool cover`.

## Questions
- Are there any other edge cases for CSRF validation that should be covered?

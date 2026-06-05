#!/usr/bin/env bash
# Standalone LLM scoring harness runner (does NOT start the app).
# Cross-compiles the test harness to a Linux binary and runs it inside a
# throwaway container on the vulfixx_default network so it can reach the local
# ollama service and the public Gemini/Mistral endpoints.
#
# Usage:
#   ./run_test.sh                       # all providers, full testset
#   TEST_PROVIDER=ollama ./run_test.sh  # one provider
#   TEST_LIMIT=10 ./run_test.sh         # first 10 CVEs
#   TEST_CVE=CVE-2023-1234 ./run_test.sh
set -euo pipefail

# Per-run binary name so a still-running container holding one binary can't
# block a rebuild of another (Windows bind-mount file lock).
BIN="test_llms_${TEST_PROVIDER:-all}_linux"
if [ "${SKIP_BUILD:-}" != "1" ]; then
  echo ">> building linux test binary ($BIN)..."
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BIN" ./cmd/test_llms/
fi

MSYS_NO_PATHCONV=1 docker run --rm \
  --network vulfixx_default \
  -v "$(pwd)":/work \
  -w /work \
  -e GEMINI_API_KEY="${GEMINI_API_KEY:?set GEMINI_API_KEY in your environment}" \
  -e GEMINI_MODEL="${GEMINI_MODEL:-gemini-3.1-flash-lite}" \
  -e GEMINI_API_VERSION="${GEMINI_API_VERSION:-v1beta}" \
  -e GEMINI_RPM="${GEMINI_RPM:-15}" \
  -e GEMINI_RPD="${GEMINI_RPD:-500}" \
  -e MISTRAL_API_KEY="${MISTRAL_API_KEY:?set MISTRAL_API_KEY in your environment}" \
  -e MISTRAL_MODEL="${MISTRAL_MODEL:-mistral-small-latest}" \
  -e MISTRAL_ENDPOINT="${MISTRAL_ENDPOINT:-https://api.mistral.ai/v1}" \
  -e LLM_ENDPOINT="${LLM_ENDPOINT:-http://ollama:11434}" \
  -e LLM_MODEL="${LLM_MODEL:-phi3-vulfixx}" \
  -e LLM_TIMEOUT="${LLM_TIMEOUT:-240}" \
  -e TEST_PROVIDER="${TEST_PROVIDER:-}" \
  -e TEST_LIMIT="${TEST_LIMIT:-}" \
  -e TEST_CVE="${TEST_CVE:-}" \
  -e VERBOSE="${VERBOSE:-}" \
  --entrypoint "/work/$BIN" \
  vulfixx-app

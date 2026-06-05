#!/bin/bash

# Start Ollama in the background
/bin/ollama serve &

# Wait for Ollama to be ready
until curl -s http://localhost:11434/api/tags > /dev/null; do
  echo "Waiting for Ollama to start..."
  sleep 2
done

echo "Ollama started, preparing model..."

# 1. Pull the base model if not present.
# NOTE: the deployed model keeps the name "phi3-vulfixx" for compatibility with
# existing LLM_MODEL configuration, but is now built on qwen2.5:3b. On the local
# CVE vendor/product extraction benchmark (66 real NVD CVEs, see run_test.sh),
# qwen2.5:3b scores 77.3% full-match vs phi3's 71.2% with the same prompt.
echo "Pulling base model qwen2.5:3b..."
ollama pull qwen2.5:3b

# 2. Create the custom Modelfile
echo "Creating Modelfile..."
cat <<EOF > /tmp/Modelfile
FROM qwen2.5:3b
PARAMETER num_ctx 8192
PARAMETER num_batch 2048
PARAMETER num_predict 512
PARAMETER temperature 0.0
SYSTEM "You are a precise security data extractor. Extract ALL affected software/hardware vendor(s), product name(s), and version(s) from the provided CVE description. Return the result ONLY as a JSON object."
EOF

# 3. Create the optimized model (named phi3-vulfixx for config compatibility)
echo "Creating optimized model phi3-vulfixx..."
ollama create phi3-vulfixx -f /tmp/Modelfile

echo "Setup complete. Bringing Ollama to foreground."
wait

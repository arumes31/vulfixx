#!/bin/bash

# Start Ollama in the background
/bin/ollama serve &

# Wait for Ollama to be ready
until curl -s http://localhost:11434/api/tags > /dev/null; do
  echo "Waiting for Ollama to start..."
  sleep 2
done

echo "Ollama started, preparing model..."

# 1. Pull the base model if not exists
echo "Pulling base model phi3..."
ollama pull phi3

# 2. Create the custom Modelfile
echo "Creating Modelfile..."
cat <<EOF > /tmp/Modelfile
FROM phi3:latest
PARAMETER num_ctx 8192
PARAMETER num_batch 2048
PARAMETER num_predict 512
PARAMETER temperature 0.0
PARAMETER stop "<|endoftext|>"
PARAMETER stop "<|end|>"
SYSTEM "You are a precise security data extractor. Extract ALL affected software/hardware vendor(s), product name(s), and version(s) from the provided CVE description. Return the result ONLY as a JSON object."
EOF

# 3. Create the optimized model
echo "Creating optimized model phi3-vulfixx..."
ollama create phi3-vulfixx -f /tmp/Modelfile

echo "Setup complete. Bringing Ollama to foreground."
wait

FROM ollama/ollama:0.35.0@sha256:2a6e883b917fc543389599dae79918f5cac9e1438890506982f44aa4f5625d01

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

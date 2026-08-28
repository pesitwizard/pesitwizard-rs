# Runtime image for the unified PeSIT Wizard node (Rust). The binary is built on the host
# (`cargo build --release`) and copied in; see build-and-test.sh.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/*
COPY pesitwizard /usr/local/bin/pesitwizard
RUN chmod +x /usr/local/bin/pesitwizard && mkdir -p /data/received /data/send /data/checkpoints /data/tls
ENV PESIT_DB=/data/pesitwizard.db \
    PESIT_CHECKPOINT_DIR=/data/checkpoints \
    PESIT_CLIENT_CHECKPOINT_DIR=/data/checkpoints-out \
    PESIT_CLIENT_RECEIVE_DIR=/data/received \
    PESIT_CLIENT_TLS_DIR=/data/tls \
    PESIT_API_PORT=8080 \
    PESIT_TRANSFER_PORT=9081 \
    RUST_LOG=info,pesit_io=info
EXPOSE 5001 8080 9081
HEALTHCHECK --interval=5s --timeout=5s --start-period=5s --retries=5 \
    CMD curl -sf http://localhost:8080/actuator/health || exit 1
ENTRYPOINT ["/usr/local/bin/pesitwizard"]

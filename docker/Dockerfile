FROM rust:1.88-bookworm AS builder

WORKDIR /app
COPY . .
RUN cargo build --release -p netscanner-server

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/netscanner-server /usr/local/bin/netscanner-server
COPY web /app/web

ENV NETSCANNER_WEB_DIR=/app/web
ENV PORT=8080

EXPOSE 8080

ENTRYPOINT ["netscanner-server"]

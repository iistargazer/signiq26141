FROM rust:1.89 as builder
WORKDIR /app
COPY . .
RUN cargo build --release --package server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/server /app/server
EXPOSE 8080
CMD ["/app/server"]

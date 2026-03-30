FROM rust:1.79-slim AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/legacy-edge .
COPY static ./static
RUN mkdir -p data
ENV PORT=8080
EXPOSE 8080
CMD ["./legacy-edge"]

# syntax=docker/dockerfile:1

# ---- frontend build ----
# Keep the same layout as the repo (web/ui beside web/internal) so vite's
# outDir "../internal/server/dist" resolves exactly like it does locally.
FROM node:20-bookworm AS ui
WORKDIR /src/web
COPY web/ui/package*.json ./ui/
RUN cd ui && npm ci
COPY web/ ./
RUN cd ui && npm run build
# dist now lives at /src/web/internal/server/dist

# ---- go build ----
FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY web/go.mod web/go.sum* ./
RUN go mod download
COPY web/ ./
# overwrite the committed dist with the freshly built frontend
COPY --from=ui /src/web/internal/server/dist/ ./internal/server/dist/
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/corplink-web ./cmd/corplink-web

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/corplink-web /usr/local/bin/corplink-web
VOLUME /etc/corplink
WORKDIR /etc/corplink
EXPOSE 6151/tcp 8989/tcp
ENTRYPOINT ["/usr/local/bin/corplink-web"]
CMD ["--listen", "0.0.0.0:6151", "/etc/corplink/config.json"]

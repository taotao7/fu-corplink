# syntax=docker/dockerfile:1

# ---- frontend build ----
FROM node:20-bookworm AS ui
WORKDIR /ui
COPY web/ui/package*.json ./
RUN npm ci
COPY web/ui/ ./
RUN npm run build
# output goes to /web/internal/server/dist via vite build.outDir; copy it out
# to a stable location for the Go build stage.
RUN mkdir -p /dist && cp -r ../internal/server/dist/* /dist/ 2>/dev/null || true

# ---- go build ----
FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY web/go.mod web/go.sum* ./
RUN go mod download
COPY web/ ./
# bring in the freshly built frontend so go:embed picks it up
COPY --from=ui /dist/ ./internal/server/dist/
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/corplink-web ./cmd/corplink-web

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/corplink-web /usr/local/bin/corplink-web
VOLUME /etc/corplink
WORKDIR /etc/corplink
EXPOSE 6151/tcp 23456/tcp
ENTRYPOINT ["/usr/local/bin/corplink-web"]
CMD ["--listen", "0.0.0.0:6151", "/etc/corplink/config.json"]

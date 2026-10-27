FROM golang:1.26-alpine AS build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# templ codegen with the version pinned in go.mod (`tool` directive), so the
# generated code matches the templ runtime it compiles against.
RUN go tool templ generate ./internal/webui/ \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/liseur-sync ./cmd/liseur-sync

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# non-root; tzdata is embedded in the binary (time/tzdata)
USER 65532:65532
ENV LISEUR_CACHE_DIR=/data/cache
COPY --from=build /out/liseur-sync /liseur-sync
EXPOSE 8585
ENTRYPOINT ["/liseur-sync"]
CMD ["serve", "-config", "/data/liseur-sync.toml"]

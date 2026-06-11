# Multi-stage build → tiny static image. All deps are pure Go and templates/
# static assets are embedded, so the final image needs nothing but the binary.
# The build stage runs on the native BUILDPLATFORM and cross-compiles to the
# TARGETARCH (amd64/arm64) — fast, no QEMU emulation needed for the Go build.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /demo .

FROM gcr.io/distroless/static-debian12
COPY --from=build /demo /demo
EXPOSE 8080
ENTRYPOINT ["/demo"]

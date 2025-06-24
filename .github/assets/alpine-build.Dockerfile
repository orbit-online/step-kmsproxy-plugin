FROM golang:1.23.6-alpine
ARG TARGETARCH
ARG VERSION
RUN apk add pcsc-lite-libs pcsc-lite-dev gcc g++
COPY . /go/src/github.com/orbit-online/step-plugin-kmsproxy
WORKDIR /go/src/github.com/orbit-online/step-plugin-kmsproxy
RUN go get ./...
RUN go build -ldflags="-X main.VERSION=${VERSION} -s -linkmode external"

FROM scratch
COPY --from=0 /go/src/github.com/orbit-online/step-plugin-kmsproxy/step-plugin-kmsproxy /

FROM golang:1.12-alpine AS build_base
ENV GO111MODULE=on
RUN apk add bash ca-certificates git gcc g++ libc-dev make python2 py-pip python-dev
WORKDIR /go/src/github.com/desoivanov/ldbgrpc
COPY go.mod .
COPY go.sum .
RUN go mod download

FROM build_base AS server_builder
COPY . .
RUN make setup
RUN make
RUN ./ldbgrpc
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go install -a -tags netgo -ldflags '-w -extldflags "-static"' ./cmd/server

FROM alpine AS ldbgrpc
RUN apk add ca-certificates
RUN mkdir -p /bin/certs
COPY --from=server_builder /go/bin/server /bin/server
COPY --from=server_builder /go/src/github.com/desoivanov/ldbgrpc/certs/* /bin/certs/
ENTRYPOINT ["/bin/server"]
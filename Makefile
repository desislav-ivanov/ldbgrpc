Setup: 
	go get -u google.golang.org/grpc
	go get -u github.com/golang/protobuf/protoc-gen-go
	pip install -U grpcio-tools

all:
	go generate ./...
	go build

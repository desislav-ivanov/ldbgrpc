.DEFAULT_GOAL := all

generators: 
	go generate ./...
	go get -u -f ./pkg/client/swagger/v2/...

godeps:
	go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
	go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger
	go get -d -u github.com/golang/protobuf/protoc-gen-go
	go install github.com/golang/protobuf/protoc-gen-go
	go get -u github.com/go-swagger/go-swagger/cmd/swagger

pydeps:
	pip install -r py-requirements.txt

echo:
	$(info ${OS} ${ARCH} ${VER} ${GRPC_GATEWAY_PATH})

setup: godeps pydeps generators

build:
	go build -o grpc_rest_server ./cmd/server
	go build -o certmanager ./pkg/cmd/certmanager 

all: generators
	go build -o grpc_rest_server ./cmd/server 
	go build -o certmanager ./pkg/cmd/certmanager

debug:
	./certmanager
	GODEBUG=http2debug=2 GRPC_TRACE=all GRPC_VERBOSITY=DEBUG GRPC_GO_LOG_VERBOSITY_LEVEL=99 GRPC_GO_LOG_SEVERITY_LEVEL=info ./grpc_rest_server

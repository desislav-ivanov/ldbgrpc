.DEFAULT_GOAL := all

generators: 
	go generate ./...

godeps:
	go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
	go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger
	go get -u github.com/golang/protobuf/protoc-gen-go

pydeps:
	pip install -r py-requirements.txt

echo:
	$(info ${OS} ${ARCH} ${VER} ${GRPC_GATEWAY_PATH})

setup: godeps pydeps generators
all: generators
	go build -o grpc_rest_server ./cmd/server 
	go build -o certmanager ./pkg/cmd/certmanager

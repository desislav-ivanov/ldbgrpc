GRPC_GATEWAY_PATH=$(shell go mod download --json | jq -r 'select ( .Path | contains("github.com/grpc-ecosystem/grpc-gateway")) | .Dir')
OS=$(shell lsb_release -si)
ARCH=$(shell uname -m | sed 's/x86_//;s/i[3-6]86/32/')
VER=$(shell lsb_release -sr)
PROTOC=$(shell command -v protoc 2> /dev/null)
APT=$(shell command -v apt 2> /dev/null)
YUM=$(shell command -v yum 2> /dev/null)

.DEFAULT_GOAL := all

generators: setup
ifndef PROTOC
	ifdef APT
		$(info apt install protoc)
	endif
endif
	go generate ./...

godeps:
	go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
	go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger
	go get -u github.com/golang/protobuf/protoc-gen-go

pydeps:
	pip install -r py-requirements.txt

echo:
	$(info ${OS} ${ARCH} ${VER} ${GRPC_GATEWAY_PATH})

setup: godeps pydeps
all:
	go build

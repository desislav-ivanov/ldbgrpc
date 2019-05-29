package main

//go:generate protoc -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis --proto_path=api/proto/v1 --go_out=plugins=grpc:api/proto/v1 service.proto
//go:generate protoc -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis --proto_path=api/proto/v1 --grpc-gateway_out=logtostderr=true:api/proto/v1  service.proto
//go:generate protoc -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis --proto_path=api/proto/v1 --swagger_out=logtostderr=true:api/proto/v1 service.proto
//go:generate bash api/scripts/python-generate.sh

package main

//disabled go:generate bash api/scripts/python-generate.sh

//go:generate protoc --proto_path=api/proto/v1 --proto_path=third_party --go_out=plugins=grpc:pkg/api/v1 service.proto
//go:generate protoc --proto_path=api/proto/v1 --proto_path=third_party --grpc-gateway_out=logtostderr=true:pkg/api/v1 service.proto
//go:generate protoc --proto_path=api/proto/v1 --proto_path=third_party --swagger_out=logtostderr=true:api/swagger/v1 service.proto

//go:generate protoc --proto_path=api/proto/v2 --proto_path=third_party --go_out=plugins=grpc:pkg/api/v2 service.proto
//go:generate protoc --proto_path=api/proto/v2 --proto_path=third_party --grpc-gateway_out=logtostderr=true,allow_delete_body=true:pkg/api/v2 service.proto
//go:generate protoc --proto_path=api/proto/v2 --proto_path=third_party --swagger_out=logtostderr=true,allow_delete_body=true:api/swagger/v2 service.proto

//go:generate swagger generate client -f api/swagger/v2/service.swagger.json -A ldbgrpc_client -t pkg/client/swagger/v2

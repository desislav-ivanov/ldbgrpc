package main

//go:generate protoc --proto_path=api/proto/v1 --go_out=plugins=grpc:api/proto/v1 cache-service.proto
func main() {
}

if [ -z "$GOPATH" ];then
    GOPATH=$HOME/go
fi
python3 -m grpc_tools.protoc -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis --proto_path=api/proto/v1 --python_out=cmd/client --grpc_python_out=cmd/client service.proto
python3 -m grpc_tools.protoc -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis --python_out=$HOME/.local/lib/python3.6/site-packages --grpc_out=$HOME/.local/lib/python3.6/site-packages --plugin=protoc-gen-grpc="$(which grpc_python_plugin)" $GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis/google/api/annotations.proto
python3 -m grpc_tools.protoc -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis --python_out=$HOME/.local/lib/python3.6/site-packages --grpc_out=$HOME/.local/lib/python3.6/site-packages --plugin=protoc-gen-grpc="$(which grpc_python_plugin)" $GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis/google/api/http.proto
touch $HOME/.local/lib/python3.6/site-packages/google/__init__.py
touch $HOME/.local/lib/python3.6/site-packages/google/api/__init__.py
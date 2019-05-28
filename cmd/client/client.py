import service_pb2
import service_pb2_grpc
import google.protobuf
import grpc
import sys
import pprint

cert = None
key = None
CA = None

with open("../../certs/client.crt",'rb') as f:
    cert = f.read()
with open("../../certs/client.key",'rb') as f:
    key = f.read()
with open("../../certs/CA.pem",'rb') as f:
    CA = f.read()
creds = grpc.ssl_channel_credentials(root_certificates=CA)
channel = grpc.secure_channel('localhost:9090',creds,options=(('grpc.ssl_target_name_override', "ldbgrpc",),))
stub = service_pb2_grpc.CacheStub(channel)

try:
    grpc.channel_ready_future(channel).result(timeout=10)
except grpc.FutureTimeoutError:
    sys.exit('Error connecting to server')
else:
    rsp = stub.GetAll(google.protobuf.empty_pb2.Empty())
    for response in rsp:
        print(response)






import service_pb2
import service_pb2_grpc
import grpc

channel = grpc.insecure_channel('localhost:9090')
stub = service_pb2_grpc.CacheStub(channel)






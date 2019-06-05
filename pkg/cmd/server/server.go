package cmd

import (
	"context"

	"github.com/desoivanov/ldbgrpc/pkg/protocol/grpc"

	v1 "github.com/desoivanov/ldbgrpc/pkg/service/v1"
	v2 "github.com/desoivanov/ldbgrpc/pkg/service/v2"
)

func RunServer(cache, cacert, cert, key, version string) error {
	ctx := context.Background()
	switch version {
	case "v1":
		svc := v1.NewService(cache)
		defer (svc.(*v1.CacheServiceServer)).Shutdown()
		return grpc.RunServerV1(ctx, svc, cacert, cert, key)
	default:
		svc := v2.NewService(cache)
		defer (svc.(*v2.CacheServiceServer)).Shutdown()
		return grpc.RunServerV2(ctx, svc, cacert, cert, key)
	}
}

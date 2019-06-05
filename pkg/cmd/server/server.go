package cmd

import (
	"context"

	"github.com/desoivanov/ldbgrpc/pkg/protocol/grpc"

	v1 "github.com/desoivanov/ldbgrpc/pkg/service/v1"
)

func RunServer(cache, cacert, cert, key string) error {
	ctx := context.Background()
	svc := v1.NewService(cache)
	defer (svc.(*v1.CacheServiceServer)).Shutdown()
	return grpc.RunServer(ctx, svc, cacert, cert, key)
}

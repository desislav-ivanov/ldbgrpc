package cmd

import (
	"context"
	"os"

	"github.com/desoivanov/ldbgrpc/pkg/protocol/grpc"

	v1 "github.com/desoivanov/ldbgrpc/pkg/service/v1"
	"github.com/sirupsen/logrus"
)

func RunServer() error {
	cachePath, cacheSet := os.LookupEnv("LDB_CACHE")
	if !cacheSet {
		logrus.Panic("Cache path not set")
	} else if len(cachePath) == 0 {
		cachePath = "cache/DefaultCache"
	}
	ctx := context.Background()
	svc := v1.NewService(cachePath)
	defer (svc.(v1.CacheServiceServer)).Shutdown()
	err := grpc.RunServer(ctx, svc, "./certs/CA/CA.pem", "./certs/SERVER/default/Server.pem", "./certs/SERVER/default/Server.key")
	return err
}

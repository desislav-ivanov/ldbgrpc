package main

//go:generate protoc --proto_path=../../api/proto/v1 --go_out=plugins=grpc:../../api/proto/v1 cache-service.proto

import (
	"net"
	"os"
	"os/signal"

	api "github.com/desoivanov/ldbgrpc/api/proto/v1"
	services "github.com/desoivanov/ldbgrpc/api/service/v1"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func main() {
	cachePath, cacheSet := os.LookupEnv("LDB_CACHE")
	if !cacheSet {
		logrus.Panic("Cache path not set")
	} else if len(cachePath) == 0 {
		cachePath = "cache/DefaultCache"
	}
	lis, err := net.Listen("tcp", ":9090")
	if err != nil {
		logrus.WithField("CachePath", cachePath).WithError(err).Panic("net.Listener() bind failed.")
	}
	s := grpc.NewServer()
	svc := services.NewService(cachePath)
	api.RegisterCacheServer(s, svc)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			logrus.WithField("CachePath", cachePath).Warn("Shutdown GRPC Server...")
			svc.(*services.CacheServiceServer).Shutdown()
			s.GracefulStop()
		}
	}()
	logrus.WithField("CachePath", cachePath).Info("Starting GRPC Server...")
	if err := s.Serve(lis); err != nil {
		logrus.WithField("CachePath", cachePath).WithError(err).Panic("GRPC Serve() failed.")
	}
}

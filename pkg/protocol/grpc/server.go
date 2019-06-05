package grpc

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"google.golang.org/grpc/credentials"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"

	"github.com/sirupsen/logrus"

	"google.golang.org/grpc"

	v1 "github.com/desoivanov/ldbgrpc/pkg/api/v1"
)

func grpcHandler(grpcServer *grpc.Server, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
}

func RunServer(ctx context.Context, v1API v1.CacheServer, CAPath string, ServerCert string, ServerKey string) error {
	screds, err := credentials.NewServerTLSFromFile(ServerCert, ServerKey)
	if err != nil {
		logrus.WithField("ServerCert", ServerCert).WithField("ServerKey", ServerKey).WithError(err).Fatal("Server Credentials.")
	}
	ccreds, err := credentials.NewClientTLSFromFile(CAPath, "ldbgrpc")
	if err != nil {
		logrus.WithField("CACert", CAPath).WithError(err).Fatal("CA Certificate.")
	}

	certPair, err := tls.LoadX509KeyPair(ServerCert, ServerKey)
	if err != nil {
		logrus.WithField("ServerCert", ServerCert).WithField("ServerKey", ServerKey).WithError(err).Fatal("Server Credentials.")
	}

	serverOptions := []grpc.ServerOption{grpc.Creds(screds)}
	dialOptions := []grpc.DialOption{grpc.WithTransportCredentials(ccreds)}

	lis, err := net.Listen("tcp", ":9090")
	if err != nil {
		logrus.WithError(err).Fatal("net.Listener() bind failed.")
	}

	s := grpc.NewServer(serverOptions...)
	v1.RegisterCacheServer(s, v1API)

	mux := http.NewServeMux()
	gwmux := runtime.NewServeMux()
	if err := v1.RegisterCacheHandlerFromEndpoint(ctx, gwmux, ":9090", dialOptions); err != nil {
		logrus.WithError(err).Fatal("RegisterCacheHandlerFromEndpoint failed.")
	}
	mux.Handle("/", gwmux)

	srv := &http.Server{
		Addr:    ":9090",
		Handler: grpcHandler(s, mux),
		TLSConfig: &tls.Config{
			ServerName:   "ldbgrpc",
			Certificates: []tls.Certificate{certPair},
			NextProtos:   []string{"h2"},
		},
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			logrus.Warn("Shutdown GRPC Server...")
			_ = srv.Shutdown(ctx)
		}
	}()
	logrus.Info("Starting GRPC Server...")
	if err := srv.Serve(tls.NewListener(lis, srv.TLSConfig)); err != nil {
		if err != http.ErrServerClosed {
			logrus.WithError(err).Fatal("GRPC Serve() failed.")
		}
		return err
	}
	return nil
}

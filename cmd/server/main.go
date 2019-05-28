package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"github.com/davecgh/go-spew/spew"

	"google.golang.org/grpc/status"

	"google.golang.org/grpc/credentials"

	api "github.com/desoivanov/ldbgrpc/api/proto/v1"
	services "github.com/desoivanov/ldbgrpc/api/service/v1"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

//code examples taken from https://github.com/philips/grpc-gateway-example/blob/master/cmd/serve.go

func grpcHandler(grpcServer *grpc.Server, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
}

// handleStreamError overrides default behavior for computing an error
// message for a server stream.
//
// It uses a default "502 Bad Gateway" HTTP code; only emits "safe"
// messages; and does not set gRPC code or details fields (so they will
// be omitted from the resulting JSON object that is sent to client).
func handleStreamError(ctx context.Context, err error) *runtime.StreamError {
	code := http.StatusBadGateway
	msg := "unexpected error"
	if s, ok := status.FromError(err); ok {
		code = runtime.HTTPStatusFromCode(s.Code())
		// default message, based on the name of the gRPC code
		msg = s.Err().Error()
		// see if error details include "safe" message to send
		// to external callers
		for _, msg := range s.Details() {
			spew.Dump(msg)
			// 	if safe, ok := msg.(*status.Status); ok {
			// 		msg = safe.Message()
			// 		break
			// 	}
		}
	}
	return &runtime.StreamError{
		HttpCode:   int32(code),
		HttpStatus: http.StatusText(code),
		Message:    msg,
	}
}

func main() {
	certpool := x509.NewCertPool()
	sCert, err := ioutil.ReadFile("../../certs/server.crt")
	if err != nil {
		logrus.WithError(err).Fatal(`ReadFile("../../certs/server.crt")`)
	}
	sKey, err := ioutil.ReadFile("../../certs/server.key")
	if err != nil {
		logrus.WithError(err).Fatal(`ReadFile("../../certs/server.key")`)
	}
	if ok := certpool.AppendCertsFromPEM(append(sCert, sKey...)); !ok {
		logrus.Fatal("Bad Certs.")
	}

	cachePath, cacheSet := os.LookupEnv("LDB_CACHE")
	if !cacheSet {
		logrus.Panic("Cache path not set")
	} else if len(cachePath) == 0 {
		cachePath = "cache/DefaultCache"
	}
	ctx := context.Background()
	lis, err := net.Listen("tcp", ":9090")
	if err != nil {
		logrus.WithField("CachePath", cachePath).WithError(err).Panic("net.Listener() bind failed.")
	}

	sopts := []grpc.ServerOption{grpc.Creds(credentials.NewClientTLSFromCert(certpool, ""))}
	creds := credentials.NewTLS(&tls.Config{
		// InsecureSkipVerify: true,
		ServerName: "ldbgrpc",
		RootCAs:    certpool,
	})
	dopts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	s := grpc.NewServer(sopts...)

	svc := services.NewService(cachePath)
	api.RegisterCacheServer(s, svc)

	mux := http.NewServeMux()

	mux.HandleFunc("/swagger.json", func(w http.ResponseWriter, req *http.Request) {
		io.Copy(w, strings.NewReader(api.Swagger))
	})

	gwmux := runtime.NewServeMux(runtime.WithStreamErrorHandler(handleStreamError))
	err = api.RegisterCacheHandlerFromEndpoint(ctx, gwmux, ":9090", dopts)
	if err != nil {
		logrus.WithError(err).Fatal("RegisterCacheHandlerFromEndpoint")
	}

	mux.Handle("/", gwmux)
	pair, err := tls.LoadX509KeyPair("../../certs/server.crt", "../../certs/server.key")
	if err != nil {
		logrus.WithError(err).Fatal(`tls.LoadX509KeyPair("../../certs/server.crt","../../certs/server.key")`)
	}

	srv := &http.Server{
		Addr:    ":9090",
		Handler: grpcHandler(s, mux),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{pair},
			NextProtos:   []string{"h2"},
		},
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			logrus.WithField("CachePath", cachePath).Warn("Shutdown GRPC Server...")
			svc.(*services.CacheServiceServer).Shutdown()
			_ = srv.Shutdown(ctx)
		}
	}()
	logrus.WithField("CachePath", cachePath).Info("Starting GRPC Server...")
	if err := srv.Serve(tls.NewListener(lis, srv.TLSConfig)); err != nil {
		if err != http.ErrServerClosed {
			logrus.WithField("CachePath", cachePath).WithError(err).Panic("GRPC Serve() failed.")
		}
	}
}

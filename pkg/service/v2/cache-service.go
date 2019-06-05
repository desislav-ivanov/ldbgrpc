package v1

import (
	"context"

	"google.golang.org/grpc/codes"

	"google.golang.org/grpc/status"

	v2 "github.com/desoivanov/ldbgrpc/pkg/api/v2"
	"github.com/golang/protobuf/ptypes/empty"

	"io"

	"github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	apiVersion = "v2"
)

type CacheServiceServer struct {
	ldb    *leveldb.DB
	logger *logrus.Entry
}

func NewService(path string) v2.CacheServer {
	var err error
	server := new(CacheServiceServer)
	server.logger = logrus.WithField("_cache_path", path).WithField("apiVersion", apiVersion)
	server.ldb, err = leveldb.OpenFile(path, nil)
	if err != nil {
		server.logger.WithError(err).Error("leveldb.OpenFile()")
		return nil
	}
	return server
}

func (s CacheServiceServer) Log() *logrus.Entry {
	return s.logger
}

func (s CacheServiceServer) checkAPI(api string) error {
	if len(api) > 0 {
		if apiVersion != api {
			return status.Errorf(codes.Unimplemented, "unsupported API version: service implements API version '%s', but asked for '%s'", apiVersion, api)
		}
	}
	return nil
}

func (s CacheServiceServer) Get(ctx context.Context, p *v2.SearchKey) (*v2.Payload, error) {
	if apiErr := s.checkAPI(p.ApiVersion); apiErr != nil {
		return nil, apiErr
	}
	if len(p.GetKey()) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "Key must be non-zero")
	}
	if s.ldb == nil {
		return nil, status.Errorf(codes.Internal, "leveldb closed")
	}
	tx, err := s.ldb.GetSnapshot()
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	defer tx.Release()
	rsp, err := tx.Get(p.GetKey(), nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	return &v2.Payload{
		Key:   p.GetKey(),
		Value: rsp}, nil
}

func (s CacheServiceServer) StreamGetMany(stream v2.Cache_StreamGetManyServer) error {
	if s.ldb == nil {
		return status.Errorf(codes.Internal, "leveldb closed")
	}
	tx, err := s.ldb.GetSnapshot()
	if err != nil {
		return status.Errorf(codes.Internal, err.Error())
	}
	defer tx.Release()
	for {
		k, e := stream.Recv()
		if e == io.EOF {
			break
		}
		if apiErr := s.checkAPI(k.ApiVersion); apiErr != nil {
			return apiErr
		}
		if len(k.GetKey()) == 0 {
			return status.Errorf(codes.InvalidArgument, "Key must be non-zero")
		}
		if v, e := tx.Get(k.GetKey(), nil); e == nil {
			if serr := stream.Send(&v2.Payload{
				Key:   k.GetKey(),
				Value: v,
			}); serr != nil {
				return status.Errorf(codes.Internal, serr.Error())
			}
		} else if e == leveldb.ErrNotFound {
			continue
		} else {
			return status.Errorf(codes.Internal, e.Error())
		}
	}
	return nil
}

func (s CacheServiceServer) StreamGetAll(empty *empty.Empty, stream v2.Cache_StreamGetAllServer) error {
	if s.ldb == nil {
		return status.Errorf(codes.Internal, "leveldb closed")
	}
	tx, err := s.ldb.GetSnapshot()
	if err != nil {
		return status.Errorf(codes.Internal, err.Error())
	}
	defer tx.Release()
	iter := tx.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		if serr := stream.Send(&v2.Payload{
			Key:   iter.Key(),
			Value: iter.Value(),
		}); serr != nil {
			return status.Errorf(codes.Internal, serr.Error())
		}
	}
	return nil
}

func (s CacheServiceServer) StreamPut(stream v2.Cache_StreamPutServer) error {
	if s.ldb == nil {
		return status.Errorf(codes.Internal, "leveldb closed")
	}
	tx, err := s.ldb.OpenTransaction()
	if err != nil {
		return status.Errorf(codes.Internal, err.Error())
	}
	for {
		m, e := stream.Recv()
		if e == io.EOF {
			break
		}
		if e != nil {
			stream.SendAndClose(&v2.Status{Code: v2.Status_Error})
			return status.Errorf(codes.Internal, e.Error())
		}
		if apiErr := s.checkAPI(m.ApiVersion); apiErr != nil {
			return apiErr
		}
		if len(m.GetKey()) == 0 || len(m.GetValue()) == 0 {
			stream.SendAndClose(&v2.Status{Code: v2.Status_Error})
			return status.Errorf(codes.InvalidArgument, "Key/Value must be non-zero")
		}
		if err := tx.Put(m.GetKey(), m.GetValue(), nil); err != nil {
			tx.Discard()
			stream.SendAndClose(&v2.Status{Code: v2.Status_Error})
			return status.Errorf(codes.Internal, err.Error())
		}
	}
	if err := tx.Commit(); err != nil {
		tx.Discard()
		stream.SendAndClose(&v2.Status{Code: v2.Status_Error})
		return status.Errorf(codes.Internal, err.Error())
	}
	stream.SendAndClose(&v2.Status{Code: v2.Status_OK})
	return nil
}

func (s CacheServiceServer) StreamDelete(stream v2.Cache_StreamDeleteServer) error {
	if s.ldb == nil {
		return status.Errorf(codes.Internal, "leveldb closed")
	}
	tx, err := s.ldb.OpenTransaction()
	if err != nil {
		return status.Errorf(codes.Internal, err.Error())
	}
	for {
		m, e := stream.Recv()
		if e == io.EOF {
			break
		}
		if e != nil {
			stream.SendAndClose(&v2.Status{Code: v2.Status_Error})
			return e
		}
		if apiErr := s.checkAPI(m.ApiVersion); apiErr != nil {
			return apiErr
		}
		if len(m.GetKey()) == 0 {
			stream.SendAndClose(&v2.Status{Code: v2.Status_Error})
			return status.Errorf(codes.InvalidArgument, "Key/Value must be non-zero")
		}
		if err := tx.Delete([]byte(m.GetKey()), nil); err != nil {
			tx.Discard()
			stream.SendAndClose(&v2.Status{Code: v2.Status_Error})
			return status.Errorf(codes.Internal, err.Error())
		}
	}
	if err := tx.Commit(); err != nil {
		tx.Discard()
		stream.SendAndClose(&v2.Status{Code: v2.Status_Error})
		return status.Errorf(codes.Internal, err.Error())
	}
	stream.SendAndClose(&v2.Status{Code: v2.Status_OK})
	return nil
}

func (s CacheServiceServer) Delete(ctx context.Context, sk *v2.SearchKey) (*v2.Status, error) {
	if apiErr := s.checkAPI(sk.ApiVersion); apiErr != nil {
		return &v2.Status{Code: v2.Status_Error}, apiErr
	}
	if len(sk.GetKey()) == 0 {
		return &v2.Status{Code: v2.Status_Error}, status.Errorf(codes.InvalidArgument, "Key/Value must be non-zero")
	}
	if s.ldb == nil {
		return &v2.Status{Code: v2.Status_Error}, status.Errorf(codes.Internal, "leveldb closed")
	}
	tx, err := s.ldb.OpenTransaction()
	if err != nil {
		return &v2.Status{Code: v2.Status_Error}, status.Errorf(codes.Internal, err.Error())
	}
	if err := tx.Delete(sk.GetKey(), nil); err != nil {
		tx.Discard()
		return &v2.Status{Code: v2.Status_Error}, status.Errorf(codes.Internal, err.Error())
	}
	if err := tx.Commit(); err != nil {
		tx.Discard()
		return &v2.Status{Code: v2.Status_Error}, status.Errorf(codes.Internal, err.Error())
	}
	return &v2.Status{Code: v2.Status_OK}, nil
}

func (s CacheServiceServer) Put(ctx context.Context, pl *v2.Payload) (*v2.Status, error) {
	if apiErr := s.checkAPI(pl.ApiVersion); apiErr != nil {
		return &v2.Status{Code: v2.Status_Error}, apiErr
	}
	if len(pl.GetKey()) == 0 || len(pl.GetValue()) == 0 {
		return &v2.Status{Code: v2.Status_Error}, status.Errorf(codes.InvalidArgument, "Key/Value must be non-zero")
	}
	if s.ldb == nil {
		return &v2.Status{Code: v2.Status_Error}, status.Errorf(codes.Internal, "leveldb closed")
	}
	tx, err := s.ldb.OpenTransaction()
	if err != nil {
		return &v2.Status{Code: v2.Status_Error}, status.Errorf(codes.Internal, err.Error())
	}
	if err := tx.Put(pl.GetKey(), pl.GetValue(), nil); err != nil {
		tx.Discard()
		return &v2.Status{Code: v2.Status_Error}, status.Errorf(codes.Internal, err.Error())
	}
	if err := tx.Commit(); err != nil {
		tx.Discard()
		return &v2.Status{Code: v2.Status_Error}, status.Errorf(codes.Internal, err.Error())
	}
	return &v2.Status{Code: v2.Status_OK}, nil
}

func (s CacheServiceServer) Shutdown() {
	if err := s.ldb.Close(); err != nil {
		s.Log().WithError(err).Panic()
	}
	s.ldb = nil
}

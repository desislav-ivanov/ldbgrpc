package v1

import (
	"context"

	"google.golang.org/grpc/codes"

	"google.golang.org/grpc/status"

	v1 "github.com/desoivanov/ldbgrpc/pkg/api/v1"
	"github.com/golang/protobuf/ptypes/empty"

	"io"

	"github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	apiVersion = "v1"
)

type CacheServiceServer struct {
	ldb    *leveldb.DB
	logger *logrus.Entry
}

func NewService(path string) v1.CacheServer {
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

func (s CacheServiceServer) Get(ctx context.Context, p *v1.SearchKey) (*v1.Payload, error) {
	if s.ldb == nil {
		return nil, status.Errorf(codes.Internal, "leveldb closed")
	}
	tx, err := s.ldb.GetSnapshot()
	if err != nil {
		return nil, err
	}
	defer tx.Release()
	rsp, err := tx.Get([]byte(p.GetKey()), nil)
	if err != nil {
		return nil, err
	}
	return &v1.Payload{
		Key:   p.GetKey(),
		Value: string(rsp)}, nil
}

func (s CacheServiceServer) GetMany(stream v1.Cache_GetManyServer) error {
	if s.ldb == nil {
		return status.Errorf(codes.Internal, "leveldb closed")
	}
	tx, err := s.ldb.GetSnapshot()
	if err != nil {
		return err
	}
	defer tx.Release()
	for {
		k, e := stream.Recv()
		if e == io.EOF {
			break
		}
		if v, e := tx.Get([]byte(k.GetKey()), nil); e == nil {
			if serr := stream.Send(&v1.Payload{
				Key:   k.GetKey(),
				Value: string(v),
			}); serr != nil {
				return serr
			}
		} else if e == leveldb.ErrNotFound {
			continue
		} else {
			return e
		}
	}
	return nil
}

func (s CacheServiceServer) GetAll(empty *empty.Empty, stream v1.Cache_GetAllServer) error {
	if s.ldb == nil {
		return status.Errorf(codes.Internal, "leveldb closed")
	}
	tx, err := s.ldb.GetSnapshot()
	if err != nil {
		return err
	}
	defer tx.Release()
	iter := tx.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		if serr := stream.Send(&v1.Payload{
			Key:   string(iter.Key()),
			Value: string(iter.Value()),
		}); serr != nil {
			return serr
		}
	}
	return nil
}

func (s CacheServiceServer) Put(stream v1.Cache_PutServer) error {
	if s.ldb == nil {
		return status.Errorf(codes.Internal, "leveldb closed")
	}
	tx, err := s.ldb.OpenTransaction()
	if err != nil {
		return err
	}
	for {
		m, e := stream.Recv()
		if e == io.EOF {
			break
		}
		if e != nil {
			stream.SendAndClose(&v1.Status{Code: v1.Status_Error})
			return e
		}
		if err := tx.Put([]byte(m.GetKey()), []byte(m.GetValue()), nil); err != nil {
			tx.Discard()
			stream.SendAndClose(&v1.Status{Code: v1.Status_Error})
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		tx.Discard()
		stream.SendAndClose(&v1.Status{Code: v1.Status_Error})
		return err
	}
	stream.SendAndClose(&v1.Status{Code: v1.Status_OK})
	return nil
}

func (s CacheServiceServer) Delete(stream v1.Cache_DeleteServer) error {
	if s.ldb == nil {
		return status.Errorf(codes.Internal, "leveldb closed")
	}
	tx, err := s.ldb.OpenTransaction()
	if err != nil {
		return err
	}
	for {
		m, e := stream.Recv()
		if e == io.EOF {
			break
		}
		if e != nil {
			stream.SendAndClose(&v1.Status{Code: v1.Status_Error})
			return e
		}
		if err := tx.Delete([]byte(m.GetKey()), nil); err != nil {
			tx.Discard()
			stream.SendAndClose(&v1.Status{Code: v1.Status_Error})
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		tx.Discard()
		stream.SendAndClose(&v1.Status{Code: v1.Status_Error})
		return err
	}
	stream.SendAndClose(&v1.Status{Code: v1.Status_OK})
	return nil
}

func (s CacheServiceServer) Shutdown() {
	s.ldb.Close()
	s.ldb = nil
}

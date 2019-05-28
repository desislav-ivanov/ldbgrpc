package CacheService

import (
	"context"

	v1 "github.com/desoivanov/ldbgrpc/api/proto/v1"
	"github.com/golang/protobuf/ptypes/empty"

	"errors"
	"io"

	"github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
)

type CacheServiceServer struct {
	ldb *leveldb.DB
}

func NewService(path string) v1.CacheServer {
	var err error
	server := new(CacheServiceServer)
	server.ldb, err = leveldb.OpenFile(path, nil)
	if err != nil {
		logrus.WithError(err).Panic()
		return nil
	}
	return server
}

func (s CacheServiceServer) Get(ctx context.Context, p *v1.SearchKey) (*v1.Payload, error) {
	if s.ldb == nil {
		return nil, errors.New("ldb closed.")
	}
	tx, err := s.ldb.GetSnapshot()
	if err != nil {
		return nil, err
	}
	defer tx.Release()
	rsp, err := tx.Get(p.GetKey(), nil)
	if err != nil {
		return nil, err
	}
	return &v1.Payload{
		Key:   p.GetKey(),
		Value: rsp}, nil
}

func (s CacheServiceServer) GetMany(stream v1.Cache_GetManyServer) error {
	if s.ldb == nil {
		return errors.New("ldb closed.")
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
		if v, e := tx.Get(k.GetKey(), nil); e == nil {
			if serr := stream.Send(&v1.Payload{
				Key:   k.GetKey(),
				Value: v,
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
		return errors.New("ldb closed.")
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
			Key:   iter.Key(),
			Value: iter.Value(),
		}); serr != nil {
			return serr
		}
	}
	return nil
}

func (s CacheServiceServer) Put(stream v1.Cache_PutServer) error {
	if s.ldb == nil {
		return errors.New("ldb closed.")
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
		if err := tx.Put(m.GetKey(), m.GetValue(), nil); err != nil {
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
		return errors.New("ldb closed.")
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
		if err := tx.Delete(m.GetKey(), nil); err != nil {
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
}

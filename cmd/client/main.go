package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/golang/protobuf/ptypes/empty"

	"github.com/davecgh/go-spew/spew"

	v1 "github.com/desoivanov/dreddit-ops/dreddit-lcache/api/proto/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

//go:generate protoc --proto_path=../../api/proto/v1 --go_out=plugins=grpc:../../api/proto/v1 cache-service.proto

func main() {
	conn, err := grpc.Dial("localhost:9090", grpc.WithInsecure())
	if err != nil {
		logrus.WithError(err).Fatal("Unable to connect.")
	}
	defer conn.Close()
	client := v1.NewCacheClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("Get()")
	p, e := client.Get(ctx, &v1.SearchKey{Key: []byte("test")})
	if e != nil {
		logrus.WithError(e).Error("client.Get()")
	} else {
		spew.Dump(p)
	}

	fmt.Println("Put()")
	stream, err := client.Put(ctx)
	if err != nil {
		logrus.WithError(e).Error("client.Put()")
		return
	}
	for i := 0; i < 10; i++ {
		key := []byte(fmt.Sprintf("Key%d", i))
		value := []byte("data")
		data := &v1.Payload{
			Key:   key,
			Value: value,
		}
		spew.Dump(data)
		if err := stream.Send(data); err != nil {
			logrus.WithError(e).Error("stream.Send()")
			break
		}
	}
	if s, err := stream.CloseAndRecv(); err != nil {
		logrus.WithError(e).Error("stream.CloseAndRecv()")
	} else {
		spew.Dump(s.GetCode())
	}
	fmt.Println("Get()")
	p, e = client.Get(ctx, &v1.SearchKey{Key: []byte("Key1")})
	if e != nil {
		logrus.WithError(e).Error("client.Get()")
	} else {
		spew.Dump(p)
	}

	fmt.Println("GetMany()")
	getstream, err := client.GetMany(ctx)
	if err != nil {
		logrus.WithError(e).Error("client.GetMany()")
		return
	}
	for i := 0; i < 10; i += 2 {
		key := []byte(fmt.Sprintf("Key%d", i))
		data := &v1.SearchKey{
			Key: key,
		}
		spew.Dump(data)
		if err := getstream.Send(data); err != nil {
			logrus.WithError(e).Error("getstream.Send()")
			break
		}
	}
	if cerr := getstream.CloseSend(); cerr != nil {
		logrus.WithError(e).Error("getstream.CloseSend()")
	}
	for {
		p, e := getstream.Recv()
		if e != nil {
			if e == io.EOF {
				break
			}
			logrus.WithError(e).Error("getstream.Recv()")
		} else {
			spew.Dump(p)
		}
	}

	fmt.Println("GetAll()")
	getallstream, gaerr := client.GetAll(ctx, &empty.Empty{})
	if gaerr != nil {
		logrus.WithError(e).Error("client.GetAll()")
		return
	}
	for {
		p, e := getallstream.Recv()
		if e != nil {
			if e == io.EOF {
				break
			}
			logrus.WithError(e).Error("getallstream.Recv()")
		} else {
			spew.Dump(p)
		}
	}

	fmt.Println("Delete()")
	deletestream, derr := client.Delete(ctx)
	if derr != nil {
		logrus.WithError(e).Error("client.Delete()")
		return
	}
	key2 := &v1.SearchKey{
		Key: []byte("Key2"),
	}
	if e := deletestream.Send(key2); e != nil {
		logrus.WithError(e).Error("deletestream.Send()")
	}
	spew.Dump(key2)
	key3 := &v1.SearchKey{
		Key: []byte("Key3"),
	}
	if e := deletestream.Send(key3); e != nil {
		logrus.WithError(e).Error("deletestream.Send()")
	}
	spew.Dump(key3)
	if s, err := deletestream.CloseAndRecv(); err != nil {
		logrus.WithError(e).Error("deletestream.CloseAndRecv()")
	} else {
		spew.Dump(s.GetCode())
	}

	fmt.Println("GetAll()")
	getallstream, gaerr = client.GetAll(ctx, &empty.Empty{})
	if gaerr != nil {
		logrus.WithError(e).Error("client.GetAll()")
		return
	}
	for {
		p, e := getallstream.Recv()
		if e != nil {
			if e == io.EOF {
				break
			}
			logrus.WithError(e).Error("getallstream.Recv()")
		} else {
			spew.Dump(p)
		}
	}

	fmt.Println("GetMany()")
	getstream, err = client.GetMany(ctx)
	if err != nil {
		logrus.WithError(e).Error("client.GetMany()")
		return
	}
	for i := 0; i < 10; i += 2 {
		key := []byte(fmt.Sprintf("Key%d", i))
		data := &v1.SearchKey{
			Key: key,
		}
		spew.Dump(data)
		if err := getstream.Send(data); err != nil {
			logrus.WithError(e).Error("getstream.Send()")
			break
		}
	}
	if cerr := getstream.CloseSend(); cerr != nil {
		logrus.WithError(e).Error("getstream.CloseSend()")
	}
	for {
		p, e := getstream.Recv()
		if e != nil {
			if e == io.EOF {
				break
			}
			logrus.WithError(e).Error("getstream.Recv()")
		} else {
			spew.Dump(p)
		}
	}

}

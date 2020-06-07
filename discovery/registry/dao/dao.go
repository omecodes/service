package dao

import (
	pb2 "github.com/omecodes/service/proto"
)

type ServicesDAO interface {
	Save(application *pb2.Info) error
	List() ([]*pb2.Info, error)
	Find(serviceName string) (*pb2.Info, error)
	Delete(serviceName string) error
	Stop() error
}

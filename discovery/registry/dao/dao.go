package dao

import (
	pb "github.com/omecodes/common/proto/service"
)

type ServicesDAO interface {
	Save(application *pb.Info) error
	List() ([]*pb.Info, error)
	Find(serviceName string) (*pb.Info, error)
	Delete(serviceName string) error
	Stop() error
}

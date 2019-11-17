package dao

import (
	"github.com/zoenion/common/dao"
	pb2 "github.com/zoenion/service/proto"
)

type ServicesDAO interface {
	Save(application *pb2.Info) error
	List() (dao.Cursor, error)
	Find(serviceName string) (*pb2.Info, error)
	Delete(serviceName string) error
	Stop() error
}

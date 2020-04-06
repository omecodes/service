package dao

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/zoenion/common/conf"
	"github.com/zoenion/common/dao"
	"github.com/zoenion/common/persist"
	pb2 "github.com/zoenion/service/proto"
)

type sqlApplicationDAO struct {
	objects persist.Objects
}

func (s *sqlApplicationDAO) Save(application *pb2.Info) error {
	name := fmt.Sprintf("%s.%s", application.Namespace, application.Name)
	return s.objects.Save(name, application)
}

func (s *sqlApplicationDAO) List() ([]*pb2.Info, error) {
	c, err := s.objects.List()
	if err != nil {
		return nil, err
	}
	// c.
	defer c.Close()

	var result []*pb2.Info
	for c.HasNext() {
		data, err := c.Next()
		if err != nil {
			return nil, err
		}
		var app pb2.Info
		err = s.objects.DecoderFunc()([]byte(data.(string)), &app)

		if err != nil {
			return nil, err
		}

		result = append(result, &app)
	}
	return result, nil
}

func (s *sqlApplicationDAO) Find(name string) (*pb2.Info, error) {
	var app *pb2.Info
	err := s.objects.Read(name, &app)
	return app, err
}

func (s *sqlApplicationDAO) Delete(applicationName string) error {
	return s.objects.Delete(applicationName)
}

func (s *sqlApplicationDAO) Stop() error {
	return s.objects.Close()
}

func (s *sqlApplicationDAO) scanApp(row dao.Row) (interface{}, error) {
	var (
		name string
		data []byte
	)

	err := row.Scan(&name, &data)
	if err != nil {
		return nil, err
	}

	app := &pb2.Info{}
	err = proto.Unmarshal(data, app)
	return app, err
}

func NewSQLDAO(prefix string, cfg conf.Map) (ServicesDAO, error) {
	db := new(sqlApplicationDAO)
	objects, err := persist.NewSQLObjectsDB(cfg, prefix)
	db.objects = objects
	return db, err
}

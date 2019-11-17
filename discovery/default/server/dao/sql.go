package dao

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/zoenion/common/conf"
	"github.com/zoenion/common/dao"
	pb2 "github.com/zoenion/service/proto"
	"log"
)

type sqlApplicationDAO struct {
	dao.SQL
}

func (s *sqlApplicationDAO) Save(application *pb2.Info) error {
	serialized, err := proto.Marshal(application)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%s:%s", application.Namespace, application.Name)
	err = s.Exec("insert", name, serialized).Error
	if err != nil {
		err = s.Exec("update", serialized, name).Error
		if err == nil {
			log.Printf("updated %s service\n", name)
		}
	}
	return err
}

func (s *sqlApplicationDAO) List() (dao.Cursor, error) {
	return s.Query("list", "app_scanner")
}

func (s *sqlApplicationDAO) Find(name string) (*pb2.Info, error) {
	var app *pb2.Info
	o, err := s.QueryOne("find", "app_scanner", name)
	if err == nil {
		app = o.(*pb2.Info)
	}
	return app, err
}

func (s *sqlApplicationDAO) Delete(applicationName string) error {
	return s.Exec("delete", applicationName).Error
}

func (s *sqlApplicationDAO) Stop() error {
	return s.DB.Close()
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
	db.SetTablePrefix(prefix).AddTableDefinition("services", `create table if not exists $prefix$_services(
		name varchar(255) not null primary key,
		encoded blob not null
	);`).
		AddStatement("insert", `insert into $prefix$_services values (?, ?);`).
		AddStatement("update", `update $prefix$_services set encoded=? where name=?;`).
		AddStatement("delete", `delete from $prefix$_services where name=?;`).
		AddStatement("find", `select * from $prefix$_services where name=?;`).
		AddStatement("list", `select * from $prefix$_services;`).
		RegisterScanner("app_scanner", dao.NewScannerFunc(db.scanApp))
	return db, db.Init(cfg)
}

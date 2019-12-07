package server

import (
	"github.com/iancoleman/strcase"
	"github.com/zoenion/common/database"
	"github.com/zoenion/service/discovery/default/server/dao"
	"github.com/zoenion/service/errors"
)

func (s *Server) initDB() error {
	var err error
	if s.configs.DB == nil {
		// todo set config path
		s.configs.DB = database.SQLiteConfig("registry.db")
	}

	s.store, err = dao.NewSQLDAO(strcase.ToSnake(s.configs.Name)+"_reg", s.configs.DB)
	if err != nil {
		return errors.Errorf("could not initialize registry store: %s", err)
	}
	return nil
}

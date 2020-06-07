package registry

import (
	"github.com/iancoleman/strcase"
	"github.com/omecodes/common/database"
	"github.com/omecodes/common/errors"
	"github.com/omecodes/service/discovery/registry/dao"
	"path/filepath"
)

func (s *Server) initDB() error {
	var err error
	if s.configs.DB == nil {
		s.configs.DB = database.SQLiteConfig(filepath.Join(s.dir, "registry.db"))
	}

	s.store, err = dao.NewSQLDAO(strcase.ToSnake(s.configs.Name)+"_reg", s.configs.DB)
	if err != nil {
		return errors.Errorf("could not initialize registry store: %s", err)
	}
	return nil
}

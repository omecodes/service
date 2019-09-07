package service

import (
	"github.com/shibukawa/configdir"
	"os"
)

type ConfDir struct {
	path string
}

func (d *ConfDir) Create() error {
	return os.MkdirAll(d.path, os.ModePerm)
}

func (d *ConfDir) Path() string {
	return d.path
}

func getDir() *ConfDir {
	dirs := configdir.New(Vendor, AppName)
	appData := dirs.QueryFolders(configdir.Global)[0]
	return &ConfDir{appData.Path}
}

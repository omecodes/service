package service

import (
	"errors"
	"sync"

	"github.com/omecodes/libome"
)

type JwtInfoStore interface {
	Save(serviceName string, info *ome.JwtInfo) error
	Get(jti string) (*ome.JwtInfo, error)
	Delete(jti string) error
	DeleteAllFromService(serviceName string) error
	Clear() error
}

type memStore struct {
	store *sync.Map
}

func (m *memStore) Save(serviceName string, info *ome.JwtInfo) error {
	m.store.Store(info.Jti, info)
	return nil
}

func (m *memStore) Get(jti string) (*ome.JwtInfo, error) {
	o, found := m.store.Load(jti)
	if !found {
		return nil, errors.New("not found")
	}
	return o.(*ome.JwtInfo), nil
}

func (m *memStore) Delete(jti string) error {
	m.store.Delete(jti)
	return nil
}

func (m *memStore) DeleteAllFromService(serviceName string) error {
	return nil
}

func (m *memStore) Clear() error {
	m.store = &sync.Map{}
	return nil
}

func NewMemInfoStore() JwtInfoStore {
	return &memStore{
		store: &sync.Map{},
	}
}

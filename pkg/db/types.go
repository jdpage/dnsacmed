package db

import (
	"database/sql"
	"sync"

	"github.com/google/uuid"
	"github.com/jdpage/dnsacmed/pkg/model"
	"go.uber.org/zap"
)

type Config struct {
	Engine     string `json:"engine"`
	Connection string `json:"connection"`
}

type acmedb struct {
	sync.Mutex
	logger *zap.Logger
	DB     *sql.DB
	engine string
}

type Database interface {
	Register(model.CIDRSlice) (*model.ACMETxt, error)
	GetByUsername(uuid.UUID) (*model.ACMETxt, error)
	GetTXTForDomain(string) ([]string, error)
	Update(*model.ACMETxtPost) error
	GetBackend() *sql.DB
	SetBackend(*sql.DB)
	Close()
	Lock()
	Unlock()
}

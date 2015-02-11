package memory

import (
	"github.com/koofr/graval"
)

type MemoryDriverFactory struct {
	Files    map[string]*MemoryFile
	Username string
	Password string
}

func (f *MemoryDriverFactory) NewDriver() (d graval.FTPDriver, err error) {
	return &MemoryDriver{
		Files:    f.Files,
		Username: f.Username,
		Password: f.Password,
	}, nil
}

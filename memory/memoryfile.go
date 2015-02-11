package memory

import (
	"os"
)

type MemoryFile struct {
	File    os.FileInfo
	Content []byte
}

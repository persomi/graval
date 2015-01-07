package graval

import (
	"io"
	"os"
	"time"
)

// For each client that connects to the server, a new FTPDriver is required.
// Create an implementation if this interface and provide it to FTPServer.
type FTPDriverFactory interface {
	NewDriver() (FTPDriver, error)
}

// You will create an implementation of this interface that speaks to your
// chosen persistence layer. graval will create a new instance of your
// driver for each client that connects and delegate to it as required.
type FTPDriver interface {
	// params  - username, password
	// returns - true if the provided details are valid
	Authenticate(username string, password string) bool

	// params  - a file path
	// returns - an int with the number of bytes in the file or -1 if the file
	//           doesn't exist
	Bytes(path string) int64

	// params  - a file path
	// returns - a time indicating when the requested path was last modified
	//         - an ok flag if the file doesn't exist or the user lacks
	//           permissions
	ModifiedTime(path string) (time.Time, bool)

	// params  - path
	// returns - true if the current user is permitted to change to the
	//           requested path
	ChangeDir(path string) bool

	// params  - path
	// returns - a collection of items describing the contents of the requested
	//           path
	DirContents(path string) ([]os.FileInfo, bool)

	// params  - path
	// returns - true if the directory was deleted
	DeleteDir(path string) bool

	// params  - path
	// returns - true if the file was deleted
	DeleteFile(path string) bool

	// params  - from_path, to_path
	// returns - true if the file was renamed
	Rename(from_path string, to_path string) bool

	// params  - path
	// returns - true if the new directory was created
	MakeDir(path string) bool

	// params  - path, position
	// returns - a string containing the file data to send to the client
	GetFile(path string, position int64) (io.ReadCloser, bool)

	// params  - desination path, an io.Reader containing the file data
	// returns - true if the data was successfully persisted
	PutFile(path string, reader io.Reader) bool
}

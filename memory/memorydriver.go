package memory

import (
	"bytes"
	"github.com/koofr/graval"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type MemoryDriver struct {
	Files    map[string]*MemoryFile
	Username string
	Password string
}

func (d *MemoryDriver) Authenticate(username string, password string) bool {
	return username == d.Username && password == d.Password
}

func (d *MemoryDriver) Bytes(path string) int64 {
	if f, ok := d.Files[path]; ok {
		return f.File.Size()
	} else {
		return -1
	}
}

func (d *MemoryDriver) ModifiedTime(path string) (time.Time, bool) {
	if f, ok := d.Files[path]; ok {
		return f.File.ModTime(), true
	} else {
		return time.Now(), false
	}
}

func (d *MemoryDriver) ChangeDir(path string) bool {
	if f, ok := d.Files[path]; ok && f.File.IsDir() {
		return true
	} else {
		return false
	}
}

func (d *MemoryDriver) DirContents(path string) ([]os.FileInfo, bool) {
	if f, ok := d.Files[path]; ok && f.File.IsDir() {
		files := make([]os.FileInfo, 0)

		if path == "/" {
			path = ""
		}

		for p, f := range d.Files {
			if strings.HasPrefix(p, path+"/") && p[len(path)+1:] != "" && !strings.Contains(p[len(path)+1:], "/") {
				files = append(files, f.File)
			}
		}

		sort.Sort(&FilesSorter{files})

		return files, true
	} else {
		return nil, false
	}
}

func (d *MemoryDriver) DeleteDir(path string) bool {
	if f, ok := d.Files[path]; ok && f.File.IsDir() {
		haschildren := false
		for p, _ := range d.Files {
			if strings.HasPrefix(p, path+"/") {
				haschildren = true
				break
			}
		}

		if haschildren {
			return false
		}

		delete(d.Files, path)

		return true
	} else {
		return false
	}
}

func (d *MemoryDriver) DeleteFile(path string) bool {
	if f, ok := d.Files[path]; ok && !f.File.IsDir() {
		delete(d.Files, path)
		return true
	} else {
		return false
	}
}

func (d *MemoryDriver) Rename(from_path string, to_path string) bool {
	if f, from_path_exists := d.Files[from_path]; from_path_exists {
		if _, to_path_exists := d.Files[to_path]; !to_path_exists {
			if _, to_path_parent_exists := d.Files[filepath.Dir(to_path)]; to_path_parent_exists {
				if f.File.IsDir() {
					delete(d.Files, from_path)
					d.Files[to_path] = &MemoryFile{graval.NewDirItem(filepath.Base(to_path)), nil}
					torename := make([]string, 0)
					for p, _ := range d.Files {
						if strings.HasPrefix(p, from_path+"/") {
							torename = append(torename, p)
						}
					}
					for _, p := range torename {
						sf := d.Files[p]
						delete(d.Files, p)
						np := to_path + p[len(from_path):]
						d.Files[np] = sf
					}
				} else {
					delete(d.Files, from_path)
					d.Files[to_path] = &MemoryFile{graval.NewFileItem(filepath.Base(to_path), f.File.Size(), f.File.ModTime()), f.Content}
				}
				return true
			} else {
				return false
			}
		} else {
			return false
		}
	} else {
		return false
	}
}

func (d *MemoryDriver) MakeDir(path string) bool {
	if _, ok := d.Files[path]; ok {
		return false
	} else {
		d.Files[path] = &MemoryFile{graval.NewDirItem(filepath.Base(path)), nil}
		return true
	}
}

func (d *MemoryDriver) GetFile(path string, position int64) (io.ReadCloser, bool) {
	if f, ok := d.Files[path]; ok && !f.File.IsDir() {
		return ioutil.NopCloser(bytes.NewReader(f.Content[position:])), true
	} else {
		return nil, false
	}
}

func (d *MemoryDriver) PutFile(path string, reader io.Reader) bool {
	if _, path_exists := d.Files[path]; !path_exists {
		if _, path_parent_exists := d.Files[filepath.Dir(path)]; path_parent_exists {
			bytes, err := ioutil.ReadAll(reader)
			if err != nil {
				return false
			}

			d.Files[path] = &MemoryFile{graval.NewFileItem(filepath.Base(path), int64(len(bytes)), time.Now().UTC()), bytes}

			return true
		} else {
			return false
		}
	} else {
		return false
	}
}

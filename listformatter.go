package graval

import (
	"bytes"
	"github.com/jehiah/go-strftime"
	"os"
	"strconv"
	"strings"
)

type listFormatter struct {
	files []os.FileInfo
}

func newListFormatter(files []os.FileInfo) *listFormatter {
	f := new(listFormatter)
	f.files = files
	return f
}

// Short returns a string that lists the collection of files by name only,
// one per line
func (formatter *listFormatter) Short() string {
	var buffer bytes.Buffer

	for _, file := range formatter.files {
		buffer.WriteString(file.Name())
		buffer.WriteString("\r\n")
	}

	buffer.WriteString("\r\n")

	return buffer.String()
}

// Detailed returns a string that lists the collection of files with extra
// detail, one per line
func (formatter *listFormatter) Detailed() string {
	var buffer bytes.Buffer

	for _, file := range formatter.files {
		buffer.WriteString(file.Mode().String())
		buffer.WriteString(" 1 owner group ")
		buffer.WriteString(lpad(strconv.Itoa(int(file.Size())), 12))
		buffer.WriteString(strftime.Format(" %b %d %H:%M ", file.ModTime()))
		buffer.WriteString(file.Name())
		buffer.WriteString("\r\n")
	}

	buffer.WriteString("\r\n")

	return buffer.String()
}

func lpad(input string, length int) (result string) {
	if len(input) < length {
		result = strings.Repeat(" ", length-len(input)) + input
	} else if len(input) == length {
		result = input
	} else {
		result = input[0:length]
	}
	return
}

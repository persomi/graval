package graval

import (
	"fmt"
	"log"
	"strings"
)

// Use an instance of this to log in a standard format
type ftpLogger struct {
	sessionId string
	quiet     bool
}

func newFtpLogger(id string, quiet bool) *ftpLogger {
	l := new(ftpLogger)
	l.sessionId = id
	l.quiet = quiet
	return l
}

func (logger *ftpLogger) Print(message interface{}) {
	if logger.quiet {
		return
	}
	log.Printf("%s   %s", logger.sessionId, message)
}

func (logger *ftpLogger) Printf(format string, v ...interface{}) {
	if logger.quiet {
		return
	}
	logger.Print(fmt.Sprintf(format, v...))
}

func (logger *ftpLogger) PrintCommand(command string, params string) {
	if logger.quiet {
		return
	}
	if command == "PASS" {
		log.Printf("%s > PASS ****", logger.sessionId)
	} else {
		log.Printf("%s > %s %s", logger.sessionId, command, params)
	}
}

func (logger *ftpLogger) PrintResponse(code int, message string) {
	if logger.quiet {
		return
	}
	log.Printf("%s < %d %s", logger.sessionId, code, strings.Replace(message, "\r\n", "\\r\\n", -1))
}

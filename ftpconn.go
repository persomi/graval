package graval

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ftpConn struct {
	conn          net.Conn
	controlReader *bufio.Reader
	controlWriter *bufio.Writer
	dataConn      ftpDataSocket
	driver        FTPDriver
	logger        *ftpLogger
	passiveOpts   *PassiveOpts
	cryptoConfig  *CryptoConfig
	serverName    string
	sessionId     string
	namePrefix    string
	reqUser       string
	user          string
	renameFrom    string
	usingTls      bool
	usingPbsz     bool
	usingProt     bool
	restPosition  int64
}

// NewftpConn constructs a new object that will handle the FTP protocol over
// an active net.TCPConn. The TCP connection should already be open before
// it is handed to this functions. driver is an instance of FTPDriver that
// will handle all auth and persistence details.
func newftpConn(tcpConn *net.TCPConn, driver FTPDriver, serverName string, passiveOpts *PassiveOpts, cryptoConfig *CryptoConfig) *ftpConn {
	c := new(ftpConn)
	c.namePrefix = "/"
	c.conn = tcpConn
	c.driver = driver
	c.sessionId = newSessionId()
	c.logger = newFtpLogger(c.sessionId)
	c.passiveOpts = passiveOpts
	c.cryptoConfig = cryptoConfig
	c.serverName = serverName

	c.usingTls = false
	c.usingPbsz = false
	c.usingProt = false

	if cryptoConfig.Implicit {
		c.startTls()
	} else {
		c.setupReaderWriter()
	}

	return c
}

// returns a random 20 char string that can be used as a unique session ID
func newSessionId() string {
	hash := sha256.New()
	_, err := io.CopyN(hash, rand.Reader, 50)
	if err != nil {
		return "????????????????????"
	}
	md := hash.Sum(nil)
	mdStr := hex.EncodeToString(md)
	return mdStr[0:20]
}

func (ftpConn *ftpConn) setupReaderWriter() {
	ftpConn.controlReader = bufio.NewReader(ftpConn.conn)
	ftpConn.controlWriter = bufio.NewWriter(ftpConn.conn)
}

type BoundCommand struct {
	CmdObj ftpCommand
	Param  string
}

// Serve starts an endless loop that reads FTP commands from the client and
// responds appropriately. terminated is a channel that will receive a true
// message when the connection closes. This loop will be running inside a
// goroutine, so use this channel to be notified when the connection can be
// cleaned up.
func (ftpConn *ftpConn) Serve() {

	ftpConn.logger.Printf("Connection Established (%s)", ftpConn.conn.RemoteAddr())
	// send welcome
	ftpConn.writeMessage(220, ftpConn.serverName)
	// read commands

	var readMutex sync.RWMutex

	cmdCh := make(chan *BoundCommand, 0)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				ftpConn.logger.Printf("Recovered in ftpConn Serve: %s", r)
			}
			ftpConn.Close()
			close(cmdCh)
		}()

		for {
			readMutex.RLock()
			line, err := ftpConn.controlReader.ReadString('\n')
			readMutex.RUnlock()
			if err != nil {
				ftpConn.logger.Printf("Error reading from control conn: %v", err)
				return
			} else {
				cmdObj := ftpConn.receiveLine(line)
				if cmdObj != nil {
					if !cmdObj.CmdObj.Async() {
						readMutex.Lock()
					}
					select {
					case cmdCh <- cmdObj:
						continue
					case _ = <-time.After(10 * time.Second):
						return
					}
				}

			}
		}
	}()

	for cmd := range cmdCh {
		cmd.CmdObj.Execute(ftpConn, cmd.Param)

		if !cmd.CmdObj.Async() {
			readMutex.Unlock()
		}
	}

	ftpConn.logger.Print("Connection Terminated")
}

// Close will manually close this connection, even if the client isn't ready.
func (ftpConn *ftpConn) Close() {
	ftpConn.conn.Close()
	if ftpConn.dataConn != nil {
		ftpConn.dataConn.Close()
	}
}

func (ftpConn *ftpConn) receiveLine(line string) (cmd *BoundCommand) {
	command, param := ftpConn.parseLine(line)
	ftpConn.logger.PrintCommand(command, param)
	cmdObj := commands[command]
	if cmdObj == nil {
		ftpConn.writeMessage(500, "Command not found")
		return
	}
	if cmdObj.RequireParam() && param == "" {
		ftpConn.writeMessage(553, "action aborted, required param missing")
		return
	} else if cmdObj.RequireAuth() && ftpConn.user == "" {
		ftpConn.writeMessage(530, "not logged in")
		return
	} else {
		cmd = &BoundCommand{cmdObj, param}
		return
	}
}

func (ftpConn *ftpConn) parseLine(line string) (string, string) {
	params := strings.SplitN(strings.Trim(line, "\r\n"), " ", 2)
	if len(params) > 0 {
		params[0] = strings.ToUpper(params[0])
	}
	if len(params) == 1 {
		return params[0], ""
	}
	return params[0], strings.TrimSpace(params[1])
}

// writeMessage will send a standard FTP response back to the client.
func (ftpConn *ftpConn) writeMessage(code int, message string) (wrote int, err error) {
	ftpConn.logger.PrintResponse(code, message)
	line := fmt.Sprintf("%d %s\r\n", code, message)
	wrote, err = ftpConn.controlWriter.WriteString(line)
	ftpConn.controlWriter.Flush()
	return
}

// writeLines will send a multiline FTP response back to the client.
func (ftpConn *ftpConn) writeLines(code int, lines ...string) (wrote int, err error) {
	message := strings.Join(lines, "\r\n") + "\r\n"
	ftpConn.logger.PrintResponse(code, message)
	wrote, err = ftpConn.controlWriter.WriteString(message)
	ftpConn.controlWriter.Flush()
	return
}

// buildPath takes a client supplied path or filename and generates a safe
// absolute path within their account sandbox.
//
//    buildpath("/")
//    => "/"
//    buildpath("one.txt")
//    => "/one.txt"
//    buildpath("/files/two.txt")
//    => "/files/two.txt"
//    buildpath("files/two.txt")
//    => "files/two.txt"
//    buildpath("/../../../../etc/passwd")
//    => "/etc/passwd"
//
// The driver implementation is responsible for deciding how to treat this path.
// Obviously they MUST NOT just read the path off disk. The probably want to
// prefix the path with something to scope the users access to a sandbox.
func (ftpConn *ftpConn) buildPath(filename string) (fullPath string) {
	low := strings.ToLower(filename)

	if len(filename) > 0 && filename[0:1] == "/" {
		fullPath = filepath.Clean(filename)
	} else if len(filename) > 0 && low != "-a" && low != "-l" && low != "-al" && low != "-la" {
		fullPath = filepath.Clean(ftpConn.namePrefix + "/" + filename)
	} else {
		fullPath = filepath.Clean(ftpConn.namePrefix)
	}
	fullPath = strings.Replace(fullPath, "//", "/", -1)
	return
}

// sendOutofbandReader will copy data from reader to the client via the currently
// open data socket. Assumes the socket is open and ready to be used.
func (ftpConn *ftpConn) sendOutofbandReader(reader io.Reader) {
	defer func() {
		ftpConn.dataConn = nil
	}()

	if !ftpConn.DataConnWait(10 * time.Second) {
		ftpConn.writeMessage(425, "Can't open data connection.")
		return
	}

	ftpConn.writeMessage(125, "Data connection already open. Transfer starting.")

	// wait for 125 and 150 messages to be writen
	time.Sleep(10 * time.Millisecond)

	// we need an empty write for TLS connection if reader is empty
	_, _ = ftpConn.dataConn.Write([]byte{})

	_, err := io.Copy(ftpConn.dataConn, reader)

	if err != nil {
		ftpConn.dataConn.Close()

		ftpConn.logger.Printf("sendOutofbandReader copy error %s", err)
		ftpConn.writeMessage(550, "Action not taken")
		return
	}

	// Chrome dies on localhost if we close connection to soon
	time.Sleep(10 * time.Millisecond)

	ftpConn.dataConn.Close()

	ftpConn.writeMessage(226, "Transfer complete.")
}

func (ftpConn *ftpConn) DataConnWait(timeout time.Duration) bool {
	if ftpConn.dataConn == nil {
		return false
	}

	return ftpConn.dataConn.Wait(timeout)
}

// sendOutofbandData will send a string to the client via the currently open
// data socket. Assumes the socket is open and ready to be used.
func (ftpConn *ftpConn) sendOutofbandData(data string) {
	ftpConn.sendOutofbandReader(bytes.NewReader([]byte(data)))
}

func (ftpConn *ftpConn) canStartTls() bool {
	return ftpConn.cryptoConfig != nil && ftpConn.cryptoConfig.TlsConfig != nil
}

func (ftpConn *ftpConn) startTls() {
	if ftpConn.usingTls {
		return
	}

	ftpConn.conn = tls.Server(ftpConn.conn, ftpConn.cryptoConfig.TlsConfig)
	ftpConn.setupReaderWriter()

	ftpConn.usingTls = true

	return
}

func (ftpConn *ftpConn) newPassiveSocket() (socket *ftpPassiveSocket, err error) {
	if ftpConn.dataConn != nil {
		ftpConn.dataConn.Close()
		ftpConn.dataConn = nil
	}

	var tlsConfig *tls.Config

	if ftpConn.usingProt {
		tlsConfig = ftpConn.cryptoConfig.TlsConfig
	}

	socket, err = newPassiveSocket(ftpConn.logger, ftpConn.passiveOpts, tlsConfig)

	if err == nil {
		ftpConn.dataConn = socket
	}

	return
}

func (ftpConn *ftpConn) newActiveSocket(host string, port int) (socket *ftpActiveSocket, err error) {
	if ftpConn.dataConn != nil {
		ftpConn.dataConn.Close()
		ftpConn.dataConn = nil
	}

	socket, err = newActiveSocket(host, port, ftpConn.logger)

	if err == nil {
		ftpConn.dataConn = socket
	}

	return
}

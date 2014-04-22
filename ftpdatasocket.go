package graval

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

type PassivePorts struct {
	Low  int
	High int
}

type PassiveOpts struct {
	ListenAddress string
	NatAddress    string
	PassivePorts  *PassivePorts
}

// A data socket is used to send non-control data between the client and
// server.
type ftpDataSocket interface {
	Host() string

	Port() int

	// the standard io.Reader interface
	Read(p []byte) (n int, err error)

	// the standard io.Writer interface
	Write(p []byte) (n int, err error)

	// the standard io.Closer interface
	Close() error
}

type ftpActiveSocket struct {
	conn   *net.TCPConn
	host   string
	port   int
	logger *ftpLogger
}

func newActiveSocket(host string, port int, logger *ftpLogger) (*ftpActiveSocket, error) {
	connectTo := buildTcpString(host, port)
	logger.Print("Opening active data connection to " + connectTo)
	raddr, err := net.ResolveTCPAddr("tcp", connectTo)
	if err != nil {
		logger.Print(err)
		return nil, err
	}
	tcpConn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		logger.Print(err)
		return nil, err
	}
	socket := new(ftpActiveSocket)
	socket.conn = tcpConn
	socket.host = host
	socket.port = port
	socket.logger = logger
	return socket, nil
}

func (socket *ftpActiveSocket) Host() string {
	return socket.host
}

func (socket *ftpActiveSocket) Port() int {
	return socket.port
}

func (socket *ftpActiveSocket) Read(p []byte) (n int, err error) {
	return socket.conn.Read(p)
}

func (socket *ftpActiveSocket) Write(p []byte) (n int, err error) {
	return socket.conn.Write(p)
}

func (socket *ftpActiveSocket) Close() error {
	return socket.conn.Close()
}

type ftpPassiveSocket struct {
	conn        *net.TCPConn
	host        string
	port        int
	ingress     chan []byte
	egress      chan []byte
	logger      *ftpLogger
	passiveOpts *PassiveOpts
}

func newPassiveSocket(logger *ftpLogger, passiveOpts *PassiveOpts) (*ftpPassiveSocket, error) {
	socket := new(ftpPassiveSocket)
	socket.ingress = make(chan []byte)
	socket.egress = make(chan []byte)
	socket.logger = logger
	socket.passiveOpts = passiveOpts

	go socket.ListenAndServe()

	retries := 100

	for {
		if socket.Port() > 0 {
			break
		}

		retries -= 1

		if retries == 0 {
			return nil, fmt.Errorf("newPassiveSocket socket port not found")
		}

		time.Sleep(100 * time.Millisecond)
	}

	return socket, nil
}

func (socket *ftpPassiveSocket) Host() string {
	return socket.host
}

func (socket *ftpPassiveSocket) Port() int {
	return socket.port
}

func (socket *ftpPassiveSocket) Read(p []byte) (n int, err error) {
	if socket.waitForOpenSocket() == false {
		return 0, errors.New("data socket unavailable")
	}
	return socket.conn.Read(p)
}

func (socket *ftpPassiveSocket) Write(p []byte) (n int, err error) {
	if socket.waitForOpenSocket() == false {
		return 0, errors.New("data socket unavailable")
	}
	return socket.conn.Write(p)
}

func (socket *ftpPassiveSocket) Close() error {
	socket.logger.Print("closing passive data socket")
	return socket.conn.Close()
}

func (socket *ftpPassiveSocket) listenHost() string {
	if socket.passiveOpts.ListenAddress != "" {
		return socket.passiveOpts.ListenAddress
	} else {
		return "0.0.0.0"
	}
}

func (socket *ftpPassiveSocket) randomPort() int {
	if socket.passiveOpts.PassivePorts != nil {
		low := socket.passiveOpts.PassivePorts.Low
		high := socket.passiveOpts.PassivePorts.High

		return low + rand.Intn(high-low-1)
	} else {
		return 0
	}
}

func (socket *ftpPassiveSocket) ListenAndServe() {
	laddr, err := net.ResolveTCPAddr("tcp", socket.listenHost()+":0")

	if err != nil {
		socket.logger.Print(err)
		return
	}

	var listener *net.TCPListener

	retries := 100

	for {
		laddr.Port = socket.randomPort()

		listener, err = net.ListenTCP("tcp4", laddr)

		if err != nil {
			if retries > 0 {
				retries -= 1
				time.Sleep(10 * time.Millisecond)
				continue
			}

			socket.logger.Print(err)

			return
		}

		break
	}

	addr := listener.Addr()

	parts := strings.Split(addr.String(), ":")

	socket.host = parts[0]

	port, err := strconv.Atoi(parts[1])

	if err == nil {
		socket.port = port
	}

	tcpConn, err := listener.AcceptTCP()

	if err != nil {
		socket.logger.Print(err)
		return
	}

	socket.conn = tcpConn
}

func (socket *ftpPassiveSocket) waitForOpenSocket() bool {
	retries := 0
	for {
		if socket.conn != nil {
			break
		}
		if retries > 3 {
			return false
		}
		socket.logger.Print("sleeping, socket isn't open")
		time.Sleep(500 * time.Millisecond)
		retries += 1
	}
	return true
}

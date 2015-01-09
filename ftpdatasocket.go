package graval

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/koofr/goevent"
	"math/rand"
	"net"
	"sync"
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

	// wait for client to connect
	Wait(timeout time.Duration) bool
}

type ftpActiveSocket struct {
	conn      *net.TCPConn
	connected *goevent.Event
	host      string
	port      int
	logger    *ftpLogger
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
	socket.connected = goevent.NewEvent()
	socket.connected.Set()
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

func (socket *ftpActiveSocket) Wait(timeout time.Duration) bool {
	return socket.connected.WaitMax(timeout)
}

type ftpPassiveSocket struct {
	listener      net.Listener
	listenerMutex *sync.RWMutex
	conn          net.Conn
	connMutex     *sync.RWMutex
	connected     *goevent.Event
	host          string
	port          int
	logger        *ftpLogger
	passiveOpts   *PassiveOpts
	tlsConfig     *tls.Config
}

func newPassiveSocket(logger *ftpLogger, passiveOpts *PassiveOpts, tlsConfig *tls.Config) (*ftpPassiveSocket, error) {
	socket := &ftpPassiveSocket{
		listener:      nil,
		listenerMutex: &sync.RWMutex{},
		conn:          nil,
		connMutex:     &sync.RWMutex{},
		connected:     goevent.NewEvent(),
		host:          "",
		port:          0,
		logger:        logger,
		passiveOpts:   passiveOpts,
		tlsConfig:     tlsConfig,
	}

	listener, err := socket.createListener()

	if err != nil {
		return nil, fmt.Errorf("newPassiveSocket socket could not be created: %s", err)
	}

	socket.listener = listener

	go socket.acceptConnection()

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

	socket.listenerMutex.Lock()
	if socket.listener != nil {
		socket.listener.Close()
		socket.listener = nil
	}
	socket.listenerMutex.Unlock()

	socket.connMutex.RLock()
	conn := socket.conn
	socket.connMutex.RUnlock()

	if conn == nil {
		return nil
	}

	return conn.Close()
}

func (socket *ftpPassiveSocket) Wait(timeout time.Duration) bool {
	return socket.connected.WaitMax(timeout)
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

func (socket *ftpPassiveSocket) createListener() (listener *net.TCPListener, err error) {
	laddr, err := net.ResolveTCPAddr("tcp", socket.listenHost()+":0")

	if err != nil {
		socket.logger.Print(err)
		return
	}

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

	addr := listener.Addr().(*net.TCPAddr)

	socket.host = addr.IP.String()
	socket.port = addr.Port

	return
}

func (socket *ftpPassiveSocket) acceptConnection() {
	socket.listenerMutex.RLock()
	listener := socket.listener
	socket.listenerMutex.RUnlock()

	if listener == nil {
		return
	}

	var conn net.Conn

	conn, err := listener.Accept()

	socket.listenerMutex.Lock()
	listener.Close()
	socket.listener = nil
	socket.listenerMutex.Unlock()

	if err != nil {
		socket.logger.Print(err)
		return
	}

	if socket.tlsConfig != nil {
		conn = tls.Server(conn, socket.tlsConfig)
	}

	socket.connMutex.Lock()
	socket.conn = conn
	socket.connMutex.Unlock()

	socket.connected.Set()
}

func (socket *ftpPassiveSocket) waitForOpenSocket() bool {
	return socket.connected.WaitMax(2 * time.Second)
}

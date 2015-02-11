package graval_test

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/jehiah/go-strftime"
	"github.com/koofr/go-netutils"
	. "github.com/koofr/graval"
	"github.com/koofr/graval/memory"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"io"
	"io/ioutil"
	"net"
	"net/textproto"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func generateCert() (cert *tls.Certificate, err error) {
	organization := "Test"
	host := "localhost"
	validFor := 365 * 24 * time.Hour
	rsaBits := 512

	certBytes, keyBytes, err := netutils.GenerateCert(organization, host, validFor, rsaBits)
	if err != nil {
		return
	}

	c, err := tls.X509KeyPair(certBytes, keyBytes)

	if err != nil {
		return
	}

	cert = &c

	return
}

type testVariant struct {
	name              string
	cryptoConfig      *CryptoConfig
	clientExplicitTls bool
	clientImplicitTls bool
}

var _ = Describe("Graval", func() {
	var host string = "127.0.0.1"
	var addr string
	var files map[string]*memory.MemoryFile
	var server *FTPServer
	var clientConn net.Conn
	var c *textproto.Conn

	quiet := os.Getenv("QUIET") != ""

	cert, certErr := generateCert()
	if certErr != nil {
		panic(certErr)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	tlsClientConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	variants := []*testVariant{
		{
			name: "Plain FTP",
			cryptoConfig: &CryptoConfig{
				Implicit:  false,
				Force:     false,
				TlsConfig: nil,
			},
			clientExplicitTls: false,
			clientImplicitTls: false,
		},
		{
			name: "Optional FTPES (client FTP)",
			cryptoConfig: &CryptoConfig{
				Implicit:  false,
				Force:     false,
				TlsConfig: tlsConfig,
			},
			clientExplicitTls: false,
			clientImplicitTls: false,
		},
		{
			name: "Optional FTPES (client FTPES)",
			cryptoConfig: &CryptoConfig{
				Implicit:  false,
				Force:     false,
				TlsConfig: tlsConfig,
			},
			clientExplicitTls: true,
			clientImplicitTls: false,
		},
		{
			name: "Forced FTPES",
			cryptoConfig: &CryptoConfig{
				Implicit:  false,
				Force:     true,
				TlsConfig: tlsConfig,
			},
			clientExplicitTls: true,
			clientImplicitTls: false,
		},
		{
			name: "FTPS",
			cryptoConfig: &CryptoConfig{
				Implicit:  true,
				Force:     false,
				TlsConfig: tlsConfig,
			},
			clientExplicitTls: false,
			clientImplicitTls: true,
		},
	}

	for _, tv := range variants {
		variant := tv

		Describe(variant.name, func() {
			cmd := func(format string, args ...interface{}) {
				_, err := c.Cmd(format, args...)
				Expect(err).NotTo(HaveOccurred())
			}

			getres := func(format string, args ...interface{}) func(int) (string, error) {
				return func(code int) (string, error) {
					cmd(format, args...)

					_, lineRes, err := c.ReadResponse(code)
					Expect(err).NotTo(HaveOccurred())

					return lineRes, err
				}
			}

			res := func(format string, args ...interface{}) func(int, string) {
				return func(code int, line string) {
					lineRes, err := getres(format, args...)(code)

					if err != nil {
						return
					}

					Expect(lineRes).To(Equal(line))
				}
			}

			resonly := func(code int, line string) {
				_, lineRes, err := c.ReadResponse(code)
				Expect(err).NotTo(HaveOccurred())

				if err != nil {
					return
				}

				Expect(lineRes).To(Equal(line))
			}

			login := func() {
				res("USER user")(331, "User name ok, password required")
				res("PASS password")(230, "Password ok, continue")
			}

			parsePasv := func(line string) (addr string, err error) {
				start := strings.Index(line, "(")
				if start == -1 {
					err = errors.New("Invalid PASV response format")
					return
				}

				end := strings.LastIndex(line, ")")
				if end == -1 {
					err = errors.New("Invalid PASV response format")
					return
				}

				pasvData := strings.Split(line[start+1:end], ",")

				if len(pasvData) != 6 {
					err = errors.New("Invalid PASV response format")
					return
				}

				ip := fmt.Sprintf("%s.%s.%s.%s", pasvData[0], pasvData[1], pasvData[2], pasvData[3])

				portPart1, err1 := strconv.Atoi(pasvData[4])
				if err1 != nil {
					err = err1
					return
				}

				portPart2, err2 := strconv.Atoi(pasvData[5])
				if err2 != nil {
					err = err2
					return
				}

				port := portPart1*256 + portPart2

				addr = fmt.Sprintf("%s:%d", ip, port)

				return
			}

			parseEpsv := func(line string) (addr string, err error) {
				start := strings.Index(line, "|||")
				if start == -1 {
					err = errors.New("Invalid EPSV response format")
					return
				}

				end := strings.LastIndex(line, "|")
				if end == -1 {
					err = errors.New("Invalid EPSV response format")
					return
				}

				port, err := strconv.Atoi(line[start+3 : end])
				if err != nil {
					return
				}

				addr = fmt.Sprintf("%s:%d", host, port)

				return
			}

			pasvConn := func() (conn net.Conn, err error) {
				line, err := getres("PASV")(227)
				if err != nil {
					return
				}

				addr, err = parsePasv(line)
				if err != nil {
					return
				}

				conn, err = net.Dial("tcp", addr)

				return
			}

			epsvConn := func() (conn net.Conn, err error) {
				line, err := getres("EPSV")(229)
				if err != nil {
					return
				}

				addr, err = parseEpsv(line)
				if err != nil {
					return
				}

				conn, err = net.Dial("tcp", addr)

				return
			}

			portConn := func() (conn net.Conn, err error) {
				host := "127.0.0.1"

				laddr, err := net.ResolveTCPAddr("tcp", host+":0")
				if !Expect(err).NotTo(HaveOccurred()) {
					return
				}

				listener, err := net.ListenTCP("tcp4", laddr)
				if !Expect(err).NotTo(HaveOccurred()) {
					return
				}

				port := listener.Addr().(*net.TCPAddr).Port

				connChan := make(chan *net.TCPConn)

				defer func() {
					if conn != nil {
						conn.Close()
					}
				}()

				go func() {
					conn, err := listener.AcceptTCP()
					Expect(err).NotTo(HaveOccurred())

					connChan <- conn
				}()

				p1 := port / 256
				p2 := port - (p1 * 256)

				quads := strings.Split(host, ".")
				target := fmt.Sprintf("%s,%s,%s,%s,%d,%d", quads[0], quads[1], quads[2], quads[3], p1, p2)

				res("PORT %s", target)(200, fmt.Sprintf("Connection established (%d)", port))

				conn = <-connChan

				return
			}

			eprtConn := func() (conn net.Conn, err error) {
				host := "127.0.0.1"

				laddr, err := net.ResolveTCPAddr("tcp", host+":0")
				if !Expect(err).NotTo(HaveOccurred()) {
					return
				}

				listener, err := net.ListenTCP("tcp4", laddr)
				if !Expect(err).NotTo(HaveOccurred()) {
					return
				}

				port := listener.Addr().(*net.TCPAddr).Port

				connChan := make(chan *net.TCPConn)

				defer func() {
					if conn != nil {
						conn.Close()
					}
				}()

				go func() {
					conn, err := listener.AcceptTCP()
					Expect(err).NotTo(HaveOccurred())

					connChan <- conn
				}()

				res("EPRT |1|%s|%d|", host, port)(200, fmt.Sprintf("Connection established (%d)", port))

				conn = <-connChan

				return
			}

			resdatapostls := func(position int64, useTls bool, format string, args ...interface{}) ([]byte, error) {
				conn, err := pasvConn()
				if !Expect(err).NotTo(HaveOccurred()) {
					return nil, err
				}
				defer conn.Close()

				if useTls {
					conn = tls.Client(conn, tlsClientConfig)
				}

				if position != -1 {
					res("REST %d", position)(350, "Requested file action pending further information")
				}

				res(format, args...)(125, "Data connection already open. Transfer starting.")

				bytes, err := ioutil.ReadAll(conn)
				if !Expect(err).NotTo(HaveOccurred()) {
					return nil, err
				}

				resonly(226, "Transfer complete.")

				return bytes, nil
			}

			resdatapos := func(position int64, format string, args ...interface{}) ([]byte, error) {
				return resdatapostls(position, false, format, args...)
			}

			resdata := func(format string, args ...interface{}) ([]byte, error) {
				return resdatapos(0, format, args...)
			}

			stor := func(path string, reader io.Reader) error {
				conn, err := pasvConn()
				if !Expect(err).NotTo(HaveOccurred()) {
					return err
				}

				res("STOR %s", path)(150, "Data transfer starting")

				_, err = io.Copy(conn, reader)
				if !Expect(err).NotTo(HaveOccurred()) {
					conn.Close()
					return err
				}

				conn.Close()

				resonly(226, "Transfer complete.")

				return nil
			}

			clientTlsUpgrade := func() {
				clientConn = tls.Client(clientConn, tlsClientConfig)
				c = textproto.NewConn(clientConn)
			}

			clientConnect := func() {
				var err error

				clientConn, err = net.Dial("tcp", addr)
				Expect(err).NotTo(HaveOccurred())

				c = textproto.NewConn(clientConn)

				if variant.clientImplicitTls {
					clientTlsUpgrade()
				}

				_, _, err = c.ReadResponse(220)
				Expect(err).NotTo(HaveOccurred())
			}

			BeforeEach(func() {
				port, err := netutils.UnusedPort()
				Expect(err).NotTo(HaveOccurred())

				files = map[string]*memory.MemoryFile{
					"/":           &memory.MemoryFile{NewDirItem(""), nil},
					"/dir":        &memory.MemoryFile{NewDirItem("dir"), nil},
					"/dir/subdir": &memory.MemoryFile{NewDirItem("subdir"), nil},
					"/file":       &memory.MemoryFile{NewFileItem("file", 42, time.Date(2015, 1, 7, 14, 21, 0, 0, time.UTC)), make([]byte, 42)},
				}

				factory := &memory.MemoryDriverFactory{files, "user", "password"}

				server = NewFTPServer(&FTPServerOpts{
					ServerName: "Test FTP server",
					Factory:    factory,
					Hostname:   host,
					Port:       port,
					PassiveOpts: &PassiveOpts{
						ListenAddress: host,
						NatAddress:    host,
						PassivePorts: &PassivePorts{
							Low:  42000,
							High: 45000,
						},
					},
					CryptoConfig: variant.cryptoConfig,
					Quiet:        quiet,
				})

				go func() {
					err1 := server.ListenAndServe()
					Expect(err1).NotTo(HaveOccurred())
				}()

				addr = fmt.Sprintf("%s:%d", host, port)

				ok := netutils.Await(addr, 10*time.Millisecond, 2*time.Second)
				Expect(ok).To(BeTrue())

				clientConnect()

				if variant.clientExplicitTls {
					res("AUTH TLS")(234, "AUTH TLS successful.")

					clientTlsUpgrade()
				}
			})

			AfterEach(func() {
				c.Close()
				server.Close()
			})

			Describe("Commands", func() {
				Describe("ABOR", func() {
					It("ABOR", func() {
						res("ABOR")(200, "OK")
					})
				})

				Describe("ALLO", func() {
					It("ALLO", func() {
						res("ALLO")(202, "Obsolete")
					})
				})

				Describe("AUTH", func() {
					It("AUTH", func() {
						res("AUTH")(553, "action aborted, required param missing")
					})

					if variant.clientExplicitTls || variant.clientImplicitTls {
						It("AUTH TLS", func() {
							res("AUTH TLS")(503, "Already using TLS.")
						})
					} else {
						if variant.cryptoConfig.TlsConfig != nil {
							It("AUTH TLS", func() {
								res("AUTH TLS")(234, "AUTH TLS successful.")
								clientTlsUpgrade()
								res("NOOP")(200, "OK")
							})

							It("AUTH TLS-C", func() {
								res("AUTH TLS-C")(234, "AUTH TLS-C successful.")
								clientTlsUpgrade()
								res("NOOP")(200, "OK")
							})

							It("AUTH SSL", func() {
								res("AUTH SSL")(234, "AUTH SSL successful.")
								clientTlsUpgrade()
								res("NOOP")(200, "OK")
							})

							It("AUTH TLS-P", func() {
								res("AUTH TLS-P")(234, "AUTH TLS-P successful.")
								clientTlsUpgrade()
								res("NOOP")(200, "OK")
							})

							It("AUTH X", func() {
								res("AUTH X")(502, "Unrecognized encryption type (use TLS or SSL).")
							})
						} else {
							It("AUTH TLS", func() {
								res("AUTH TLS")(500, "Command not found")
							})
						}
					}
				})

				Describe("CDUP", func() {
					It("CDUP", func() {
						res("CDUP")(530, "not logged in")
					})

					It("CDUP", func() {
						login()
						res("CDUP")(250, "Directory changed to /")
					})

					It("CDUP", func() {
						login()
						res("CWD dir")(250, "Directory changed to /dir")
						res("CWD subdir")(250, "Directory changed to /dir/subdir")
						res("CDUP")(250, "Directory changed to /dir")
						res("CDUP")(250, "Directory changed to /")
					})
				})

				Describe("CWD", func() {
					It("CWD", func() {
						res("CWD")(553, "action aborted, required param missing")
					})

					It("CWD dir", func() {
						res("CWD dir")(530, "not logged in")
					})

					It("CWD dir", func() {
						login()
						res("CWD dir")(250, "Directory changed to /dir")
					})

					It("CWD /dir", func() {
						login()
						res("CWD /dir")(250, "Directory changed to /dir")
					})

					It("CWD subdir", func() {
						login()
						res("CWD subdir")(550, "Action not taken")
					})

					It("CWD /dir/subdir", func() {
						login()
						res("CWD /dir/subdir")(250, "Directory changed to /dir/subdir")
					})
				})

				Describe("DELE", func() {
					It("DELE", func() {
						res("DELE")(553, "action aborted, required param missing")
					})

					It("DELE file", func() {
						res("DELE file")(530, "not logged in")
					})

					It("DELE file", func() {
						login()
						res("DELE file")(250, "File deleted")
					})

					It("DELE nonexisting", func() {
						login()
						res("DELE nonexisting")(550, "Action not taken")
					})

					It("DELE dir", func() {
						login()
						res("DELE dir")(550, "Action not taken")
					})
				})

				Describe("EPRT", func() {
					It("EPRT", func() {
						res("EPRT")(553, "action aborted, required param missing")
					})

					It("EPRT", func() {
						res("EPRT |1|127.0.0.1|6275|")(530, "not logged in")
					})

					It("EPRT", func() {
						login()

						conn, err := eprtConn()
						Expect(err).NotTo(HaveOccurred())

						conn.Close()
					})

					It("EPRT", func() {
						login()

						host := "127.0.0.1"

						port, err := netutils.UnusedPort()
						Expect(err).NotTo(HaveOccurred())

						res("EPRT |1|%s|%d|", host, port)(425, "Data connection failed")
					})

					It("EPRT", func() {
						login()

						res("EPRT |42|invalid|invalid|")(522, "Network protocol not supported, use (1,2)")
					})
				})

				Describe("EPSV", func() {
					It("EPSV", func() {
						res("EPSV")(530, "not logged in")
					})

					It("EPSV", func() {
						login()

						conn, err := epsvConn()
						Expect(err).NotTo(HaveOccurred())

						conn.Close()
					})

					It("EPSV EPSV", func() {
						login()

						conn, err := epsvConn()
						Expect(err).NotTo(HaveOccurred())

						readErrChan := make(chan error)

						go func() {
							_, readErr := conn.Read([]byte{0})

							readErrChan <- readErr
						}()

						conn1, err := epsvConn()
						Expect(err).NotTo(HaveOccurred())

						readErr := <-readErrChan
						Expect(readErr).To(HaveOccurred())

						conn1.Close()
					})

					It("EPSV tcp tcp", func() {
						login()

						line, err := getres("EPSV")(229)
						Expect(err).NotTo(HaveOccurred())

						addr, err = parseEpsv(line)
						Expect(err).NotTo(HaveOccurred())

						conn, err := net.Dial("tcp", addr)
						Expect(err).NotTo(HaveOccurred())

						conn.Close()

						// give server goroutine a change to accept conn and close listener
						runtime.Gosched()
						time.Sleep(10 * time.Millisecond)

						conn, err = net.Dial("tcp", addr)
						Expect(err).To(HaveOccurred())
					})
				})

				Describe("FEAT", func() {
					It("FEAT", func() {
						res("FEAT")(211, "Features supported:\n AUTH TLS\n AUTH SSL\n EPRT\n EPSV\n MDTM\n PBSZ\n PROT\n SIZE\n UTF8\nEnd FEAT.")
					})
				})

				Describe("LIST", func() {
					It("LIST", func() {
						res("LIST")(530, "not logged in")
					})

					It("LIST dir", func() {
						res("LIST dir")(530, "not logged in")
					})

					It("LIST", func() {
						login()
						res("LIST")(425, "Can't open data connection.")
					})

					It("LIST", func() {
						login()

						bytes, err := resdata("LIST")
						Expect(err).NotTo(HaveOccurred())

						Expect(string(bytes)).To(Equal(fmt.Sprintf(
							"drw-rw-rw- 1 owner group            0 %s dir\r\n"+
								"-rw-rw-rw- 1 owner group           42 Jan 07 14:21 file\r\n"+
								"\r\n",
							strftime.Format("%b %d %H:%M", files["/dir"].File.ModTime()))))
					})

					It("LIST dir", func() {
						login()

						bytes, err := resdata("LIST dir")
						Expect(err).NotTo(HaveOccurred())

						Expect(string(bytes)).To(Equal(fmt.Sprintf(
							"drw-rw-rw- 1 owner group            0 %s subdir\r\n"+
								"\r\n",
							strftime.Format("%b %d %H:%M", files["/dir/subdir"].File.ModTime()))))
					})

					It("LIST nonexisting", func() {
						login()

						conn, err := pasvConn()
						Expect(err).NotTo(HaveOccurred())
						defer conn.Close()

						res("LIST nonexisting")(450, "File not available")
					})

					It("LIST LIST", func() {
						login()

						_, err := resdata("LIST")
						Expect(err).NotTo(HaveOccurred())

						res("LIST")(425, "Can't open data connection.")
					})
				})

				Describe("MDTM", func() {
					It("MDTM", func() {
						res("MDTM")(553, "action aborted, required param missing")
					})

					It("MDTM file", func() {
						res("MDTM file")(530, "not logged in")
					})

					It("MDTM file", func() {
						login()
						res("MDTM file")(213, "20150107142100")
					})

					It("MDTM nonexisting", func() {
						login()
						res("MDTM nonexisting")(450, "File not available")
					})

					It("MDTM dir", func() {
						login()
						res("MDTM dir")(213, strftime.Format("%Y%m%d%H%M%S", files["/dir"].File.ModTime()))
					})
				})

				Describe("MKD", func() {
					It("MKD", func() {
						res("MKD")(553, "action aborted, required param missing")
					})

					It("MKD newdir", func() {
						res("MKD newdir")(530, "not logged in")
					})

					It("MKD newdir", func() {
						login()
						res("MKD newdir")(257, "Directory created")
					})

					It("MKD file", func() {
						login()
						res("MKD file")(550, "Action not taken")
					})

					It("MKD dir", func() {
						login()
						res("MKD dir")(550, "Action not taken")
					})
				})

				Describe("MODE", func() {
					It("MODE", func() {
						res("MODE")(553, "action aborted, required param missing")
					})

					It("MODE S", func() {
						res("MODE S")(530, "not logged in")
					})

					It("MODE S", func() {
						login()
						res("MODE S")(200, "OK")
					})

					It("MODE file", func() {
						login()
						res("MODE file")(504, "MODE is an obsolete command")
					})
				})

				Describe("NLST", func() {
					It("NLST", func() {
						res("NLST")(530, "not logged in")
					})

					It("NLST dir", func() {
						res("NLST dir")(530, "not logged in")
					})

					It("NLST", func() {
						login()
						res("NLST")(425, "Can't open data connection.")
					})

					It("NLST", func() {
						login()

						bytes, err := resdata("NLST")
						Expect(err).NotTo(HaveOccurred())

						Expect(string(bytes)).To(Equal("dir\r\nfile\r\n\r\n"))
					})

					It("NLST dir", func() {
						login()

						bytes, err := resdata("NLST dir")
						Expect(err).NotTo(HaveOccurred())

						Expect(string(bytes)).To(Equal("subdir\r\n\r\n"))
					})

					It("NLST nonexisting", func() {
						login()

						conn, err := pasvConn()
						Expect(err).NotTo(HaveOccurred())
						defer conn.Close()

						res("NLST nonexisting")(450, "File not available")
					})

					It("NLST NLST", func() {
						login()

						_, err := resdata("NLST")
						Expect(err).NotTo(HaveOccurred())

						res("NLST")(425, "Can't open data connection.")
					})
				})

				Describe("NOOP", func() {
					It("NOOP", func() {
						res("NOOP")(200, "OK")
					})
				})

				Describe("OPTS", func() {
					It("OPTS", func() {
						res("OPTS")(530, "not logged in")
					})

					It("OPTS", func() {
						login()
						res("OPTS")(500, "Command not found")
					})

					It("OPTS UTF8 ON", func() {
						login()
						res("OPTS UTF8 ON")(200, "OK")
					})

					It("OPTS UTF8", func() {
						login()
						res("OPTS UTF8")(200, "OK")
					})
				})

				Describe("PASS", func() {
					It("PASS", func() {
						res("PASS")(553, "action aborted, required param missing")
					})

					It("PASS password", func() {
						res("PASS password")(530, "Incorrect password, not logged in")
					})

					It("USER user PASS password", func() {
						res("USER user")(331, "User name ok, password required")
						res("PASS password")(230, "Password ok, continue")
					})
				})

				Describe("PASV", func() {
					It("PASV", func() {
						res("PASV")(530, "not logged in")
					})

					It("PASV", func() {
						login()

						conn, err := pasvConn()
						Expect(err).NotTo(HaveOccurred())

						conn.Close()
					})

					It("PASV PASV", func() {
						login()

						conn, err := pasvConn()
						Expect(err).NotTo(HaveOccurred())

						readErrChan := make(chan error)

						go func() {
							_, readErr := conn.Read([]byte{0})

							readErrChan <- readErr
						}()

						conn1, err := pasvConn()
						Expect(err).NotTo(HaveOccurred())

						readErr := <-readErrChan
						Expect(readErr).To(HaveOccurred())

						conn1.Close()
					})

					It("PASV PORT", func() {
						login()

						conn, err := pasvConn()
						Expect(err).NotTo(HaveOccurred())

						readErrChan := make(chan error)

						go func() {
							_, readErr := conn.Read([]byte{0})

							readErrChan <- readErr
						}()

						conn1, err := portConn()
						Expect(err).NotTo(HaveOccurred())

						readErr := <-readErrChan
						Expect(readErr).To(HaveOccurred())

						conn1.Close()
					})

					It("should not connect to the same passive addr more than once", func() {
						login()
						line, err := getres("PASV")(227)

						if err != nil {
							return
						}

						pasvAddr, err := parsePasv(line)
						Expect(err).NotTo(HaveOccurred())

						conn, err := net.Dial("tcp", pasvAddr)
						Expect(err).NotTo(HaveOccurred())

						conn.Close()

						conn, err = net.Dial("tcp", pasvAddr)
						Expect(err).To(HaveOccurred())
					})

					It("should close pasive listener when another passive connection is requested", func() {
						login()
						line, err := getres("PASV")(227)

						if err != nil {
							return
						}

						pasvAddr, err := parsePasv(line)
						Expect(err).NotTo(HaveOccurred())

						line, err = getres("PASV")(227)

						if err != nil {
							return
						}

						pasvAddr1, err := parsePasv(line)
						Expect(err).NotTo(HaveOccurred())

						_, err = net.Dial("tcp", pasvAddr)
						Expect(err).To(HaveOccurred())

						_, err = net.Dial("tcp", pasvAddr1)
						Expect(err).NotTo(HaveOccurred())
					})

					It("should close passive listener after control connection is closed", func() {
						login()
						line, err := getres("PASV")(227)

						if err != nil {
							return
						}

						pasvAddr, err := parsePasv(line)
						Expect(err).NotTo(HaveOccurred())

						res("QUIT")(221, "Goodbye.")

						c.Cmd("NOOP")
						c.ReadResponse(0)

						_, err = net.Dial("tcp", pasvAddr)
						Expect(err).To(HaveOccurred())
					})
				})

				Describe("PBSZ", func() {
					if variant.clientExplicitTls || variant.clientImplicitTls {
						It("PBSZ", func() {
							res("PBSZ")(200, "PBSZ=0 successful.")
						})
					} else {
						It("PBSZ", func() {
							res("PBSZ")(503, "PBSZ not allowed on insecure control connection.")
						})
					}
				})

				Describe("PORT", func() {
					It("PORT", func() {
						res("PORT")(553, "action aborted, required param missing")
					})

					It("PORT", func() {
						res("PORT 127,0,0,1,15,13")(530, "not logged in")
					})

					It("PORT", func() {
						login()

						host := "127.0.0.1"

						port, err := netutils.UnusedPort()
						Expect(err).NotTo(HaveOccurred())

						p1 := port / 256
						p2 := port - (p1 * 256)

						quads := strings.Split(host, ".")
						target := fmt.Sprintf("%s,%s,%s,%s,%d,%d", quads[0], quads[1], quads[2], quads[3], p1, p2)

						res("PORT %s", target)(425, "Data connection failed")
					})

					It("PORT invalid host", func() {
						login()

						host := "127.0.0.1.X"

						port, err := netutils.UnusedPort()
						Expect(err).NotTo(HaveOccurred())

						p1 := port / 256
						p2 := port - (p1 * 256)

						quads := strings.Split(host, ".")
						target := fmt.Sprintf("%s,%s,%s,%s,%d,%d", quads[0], quads[1], quads[2], quads[3], p1, p2)

						res("PORT %s", target)(425, "Data connection failed")
					})

					It("PORT", func() {
						login()

						conn, err := portConn()
						Expect(err).NotTo(HaveOccurred())

						conn.Close()
					})
				})

				Describe("PROT", func() {
					if variant.clientExplicitTls || variant.clientImplicitTls {
						It("PROT C", func() {
							res("PROT C")(503, "You must issue the PBSZ command prior to PROT.")
						})

						It("PROT C", func() {
							res("PBSZ")(200, "PBSZ=0 successful.")
							res("PROT C")(200, "Protection set to Clear")
						})

						It("PROT P", func() {
							res("PBSZ")(200, "PBSZ=0 successful.")
							res("PROT P")(200, "Protection set to Private")

							login()

							bytes, err := resdatapostls(2, true, "RETR file")
							Expect(err).NotTo(HaveOccurred())

							Expect(bytes).To(HaveLen(40))
						})

						It("PROT S", func() {
							res("PBSZ")(200, "PBSZ=0 successful.")
							res("PROT S")(521, "PROT S unsupported (use C or P).")
						})

						It("PROT E", func() {
							res("PBSZ")(200, "PBSZ=0 successful.")
							res("PROT E")(521, "PROT E unsupported (use C or P).")
						})

						It("PROT X", func() {
							res("PBSZ")(200, "PBSZ=0 successful.")
							res("PROT X")(502, "Unrecognized PROT type (use C or P).")
						})
					} else {
						It("PROT", func() {
							res("PROT")(503, "PROT not allowed on insecure control connection.")
						})
					}
				})

				Describe("PWD", func() {
					It("PWD", func() {
						res("PWD")(530, "not logged in")
					})

					It("PWD", func() {
						login()
						res("PWD")(257, "\"/\" is the current directory")
					})

					It("CWD dir PWD", func() {
						login()
						res("CWD dir")(250, "Directory changed to /dir")
						res("PWD")(257, "\"/dir\" is the current directory")
					})
				})

				Describe("QUIT", func() {
					It("QUIT", func() {
						res("QUIT")(221, "Goodbye.")

						c.Cmd("NOOP")
						_, _, err := c.ReadResponse(0)
						Expect(err).To(Equal(io.EOF))
					})
				})

				Describe("REST", func() {
					It("REST", func() {
						res("REST")(553, "action aborted, required param missing")
					})

					It("REST 2", func() {
						res("REST 2")(530, "not logged in")
					})

					It("REST 2", func() {
						login()

						bytes, err := resdatapos(2, "RETR file")
						Expect(err).NotTo(HaveOccurred())

						Expect(bytes).To(HaveLen(40))
					})

					It("REST -1", func() {
						login()
						res("REST -1")(500, "Invalid parameter")
					})

					It("REST a", func() {
						login()
						res("REST a")(500, "Invalid parameter")
					})
				})

				Describe("RETR", func() {
					It("RETR", func() {
						res("RETR")(553, "action aborted, required param missing")
					})

					It("RETR file", func() {
						res("RETR file")(530, "not logged in")
					})

					It("RETR file", func() {
						login()
						res("RETR file")(425, "Can't open data connection.")
					})

					It("RETR file", func() {
						login()

						bytes, err := resdata("RETR file")
						Expect(err).NotTo(HaveOccurred())

						Expect(bytes).To(HaveLen(42))
					})

					It("RETR nonexisting", func() {
						login()

						conn, err := pasvConn()
						Expect(err).NotTo(HaveOccurred())
						defer conn.Close()

						res("RETR nonexisting")(551, "File not available")
					})

					It("RETR bigabort", func() {
						login()

						stor("bigabort", bytes.NewReader(make([]byte, 20*1024*1024)))

						conn, err := pasvConn()
						Expect(err).NotTo(HaveOccurred())
						defer conn.Close()

						res("RETR bigabort")(125, "Data connection already open. Transfer starting.")

						r := io.LimitReader(conn, 2*1024*1024)

						_, err = ioutil.ReadAll(r)
						Expect(err).NotTo(HaveOccurred())

						conn.Close()

						resonly(550, "Action not taken")
					})
				})

				Describe("RNFR", func() {
					It("RNFR", func() {
						res("RNFR")(553, "action aborted, required param missing")
					})

					It("RNFR file", func() {
						res("RNFR file")(530, "not logged in")
					})

					It("RNFR file", func() {
						login()
						res("RNFR file")(350, "Requested file action pending further information.")
					})

					It("RNFR dir", func() {
						login()
						res("RNFR dir")(350, "Requested file action pending further information.")
					})

					It("RNFR nonexisting", func() {
						login()
						res("RNFR nonexisting")(350, "Requested file action pending further information.")
					})
				})

				Describe("RNTO", func() {
					It("RNTO", func() {
						res("RNTO")(553, "action aborted, required param missing")
					})

					It("RNTO renamed", func() {
						res("RNTO renamed")(530, "not logged in")
					})

					It("RNTO renamed", func() {
						login()
						res("RNTO renamed")(550, "Action not taken")
					})

					It("RNFR file RNTO renamed", func() {
						login()
						res("RNFR file")(350, "Requested file action pending further information.")
						res("RNTO renamed")(250, "File renamed")
					})

					It("RNFR file RNTO file", func() {
						login()
						res("RNFR file")(350, "Requested file action pending further information.")
						res("RNTO file")(550, "Action not taken")
					})

					It("RNFR file RNTO /nonexisting/renamed", func() {
						login()
						res("RNFR file")(350, "Requested file action pending further information.")
						res("RNTO /nonexisting/renamed")(550, "Action not taken")
					})

					It("RNFR dir RNTO dirrenamed", func() {
						login()
						res("RNFR dir")(350, "Requested file action pending further information.")
						res("RNTO dirrenamed")(250, "File renamed")
					})

					It("RNFR nonexisting RNTO renamed", func() {
						login()
						res("RNFR nonexisting")(350, "Requested file action pending further information.")
						res("RNTO renamed")(550, "Action not taken")
					})
				})

				Describe("RMD", func() {
					It("RMD", func() {
						res("RMD")(553, "action aborted, required param missing")
					})

					It("RMD dir", func() {
						res("RMD dir")(530, "not logged in")
					})

					It("RMD dir", func() {
						login()
						res("RMD dir")(550, "Action not taken")
					})

					It("RMD dir/subdir", func() {
						login()
						res("RMD dir/subdir")(250, "Directory deleted")
					})

					It("RMD file", func() {
						login()
						res("RMD file")(550, "Action not taken")
					})

					It("RMD nonexsiting", func() {
						login()
						res("RMD nonexsiting")(550, "Action not taken")
					})
				})

				Describe("SIZE", func() {
					It("SIZE", func() {
						res("SIZE")(553, "action aborted, required param missing")
					})

					It("SIZE file", func() {
						res("SIZE file")(530, "not logged in")
					})

					It("SIZE file", func() {
						login()
						res("SIZE file")(213, "42")
					})

					It("SIZE dir", func() {
						login()
						res("SIZE dir")(213, "0")
					})

					It("SIZE nonexistent", func() {
						login()
						res("SIZE nonexistent")(450, "file not available")
					})
				})

				Describe("STOR", func() {
					It("STOR", func() {
						res("STOR")(553, "action aborted, required param missing")
					})

					It("STOR newfile", func() {
						res("STOR newfile")(530, "not logged in")
					})

					It("STOR newfile", func() {
						login()
						res("STOR newfile")(425, "Can't open data connection.")
					})

					It("STOR file", func() {
						login()
						res("STOR file")(425, "Can't open data connection.")
					})

					It("STOR newfile", func() {
						login()
						stor("newfile", bytes.NewBufferString("12345"))
					})

					It("STOR file", func() {
						login()

						conn, err := pasvConn()
						Expect(err).NotTo(HaveOccurred())
						defer conn.Close()

						res("STOR file")(450, "error during transfer")
					})
				})

				Describe("STRU", func() {
					It("STRU", func() {
						res("STRU")(553, "action aborted, required param missing")
					})

					It("STRU F", func() {
						res("STRU F")(530, "not logged in")
					})

					It("STRU F", func() {
						login()
						res("STRU F")(200, "OK")
					})

					It("STRU X", func() {
						login()
						res("STRU X")(504, "STRU is an obsolete command")
					})
				})

				Describe("SYST", func() {
					It("SYST", func() {
						res("SYST")(530, "not logged in")
					})

					It("SYST", func() {
						login()
						res("SYST")(215, "UNIX Type: L8")
					})
				})

				Describe("TYPE", func() {
					It("TYPE", func() {
						res("TYPE")(530, "not logged in")
					})

					It("TYPE A", func() {
						res("TYPE xxx")(530, "not logged in")
					})

					It("TYPE", func() {
						login()
						res("TYPE")(500, "Invalid type")
					})

					It("TYPE A", func() {
						login()
						res("TYPE A")(200, "Type set to ASCII")
					})

					It("TYPE I", func() {
						login()
						res("TYPE I")(200, "Type set to binary")
					})

					It("TYPE X", func() {
						login()
						res("TYPE X")(500, "Invalid type")
					})
				})

				Describe("USER", func() {
					It("USER", func() {
						res("USER")(553, "action aborted, required param missing")
					})

					It("USER user", func() {
						res("USER user")(331, "User name ok, password required")
					})

					if variant.cryptoConfig.Force {
						It("USER user (forced TLS)", func() {
							c.Close()
							clientConnect()

							res("USER user")(534, "Policy Requires SSL")
						})
					}

					It("USER invalid", func() {
						res("USER invalid")(331, "User name ok, password required")
					})
				})

				Describe("XCUP", func() {
					It("XCUP", func() {
						res("XCUP")(530, "not logged in")
					})

					It("XCUP", func() {
						login()
						res("XCUP")(250, "Directory changed to /")
					})

					It("XCUP", func() {
						login()
						res("CWD dir")(250, "Directory changed to /dir")
						res("CWD subdir")(250, "Directory changed to /dir/subdir")
						res("XCUP")(250, "Directory changed to /dir")
						res("XCUP")(250, "Directory changed to /")
					})
				})

				Describe("XCWD", func() {
					It("XCWD", func() {
						res("XCWD")(553, "action aborted, required param missing")
					})

					It("XCWD dir", func() {
						res("XCWD dir")(530, "not logged in")
					})

					It("XCWD dir", func() {
						login()
						res("XCWD dir")(250, "Directory changed to /dir")
					})

					It("XCWD /dir", func() {
						login()
						res("XCWD /dir")(250, "Directory changed to /dir")
					})

					It("XCWD subdir", func() {
						login()
						res("XCWD subdir")(550, "Action not taken")
					})

					It("XCWD /dir/subdir", func() {
						login()
						res("XCWD /dir/subdir")(250, "Directory changed to /dir/subdir")
					})
				})

				Describe("XMKD", func() {
					It("XMKD", func() {
						res("XMKD")(553, "action aborted, required param missing")
					})

					It("XMKD newdir", func() {
						res("XMKD newdir")(530, "not logged in")
					})

					It("XMKD newdir", func() {
						login()
						res("XMKD newdir")(257, "Directory created")
					})

					It("XMKD file", func() {
						login()
						res("XMKD file")(550, "Action not taken")
					})

					It("XMKD dir", func() {
						login()
						res("XMKD dir")(550, "Action not taken")
					})
				})

				Describe("XPWD", func() {
					It("XPWD", func() {
						res("XPWD")(530, "not logged in")
					})

					It("XPWD", func() {
						login()
						res("XPWD")(257, "\"/\" is the current directory")
					})

					It("CWD dir XPWD", func() {
						login()
						res("CWD dir")(250, "Directory changed to /dir")
						res("XPWD")(257, "\"/dir\" is the current directory")
					})
				})

				Describe("XRMD", func() {
					It("XRMD", func() {
						res("XRMD")(553, "action aborted, required param missing")
					})

					It("XRMD dir", func() {
						res("XRMD dir")(530, "not logged in")
					})

					It("XRMD dir", func() {
						login()
						res("XRMD dir")(550, "Action not taken")
					})

					It("XRMD dir/subdir", func() {
						login()
						res("XRMD dir/subdir")(250, "Directory deleted")
					})

					It("XRMD file", func() {
						login()
						res("XRMD file")(550, "Action not taken")
					})

					It("XRMD nonexsiting", func() {
						login()
						res("XRMD nonexsiting")(550, "Action not taken")
					})
				})

				Describe("NOTFOUND", func() {
					It("NOTFOUND", func() {
						res("NOTFOUND")(500, "Command not found")
					})
				})

			})

		})

	}

})

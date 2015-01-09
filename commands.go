package graval

import (
	"fmt"
	"github.com/jehiah/go-strftime"
	"github.com/koofr/go-ioutils"
	"strconv"
	"strings"
	"time"
)

type ftpCommand interface {
	RequireParam() bool
	RequireAuth() bool
	Async() bool
	Execute(*ftpConn, string)
}

type commandMap map[string]ftpCommand

var (
	commands = commandMap{
		"ABOR": commandAbor{},
		"ALLO": commandAllo{},
		"AUTH": commandAuth{},
		"CDUP": commandCdup{},
		"CWD":  commandCwd{},
		"DELE": commandDele{},
		"EPRT": commandEprt{},
		"EPSV": commandEpsv{},
		"FEAT": commandFeat{},
		"LIST": commandList{},
		"NLST": commandNlst{},
		"MDTM": commandMdtm{},
		"MKD":  commandMkd{},
		"MODE": commandMode{},
		"NOOP": commandNoop{},
		"OPTS": commandOpts{},
		"PASS": commandPass{},
		"PASV": commandPasv{},
		"PBSZ": commandPbsz{},
		"PORT": commandPort{},
		"PROT": commandProt{},
		"PWD":  commandPwd{},
		"QUIT": commandQuit{},
		"REST": commandRest{},
		"RETR": commandRetr{},
		"RNFR": commandRnfr{},
		"RNTO": commandRnto{},
		"RMD":  commandRmd{},
		"SIZE": commandSize{},
		"STOR": commandStor{},
		"STRU": commandStru{},
		"SYST": commandSyst{},
		"TYPE": commandType{},
		"USER": commandUser{},
		"XCUP": commandCdup{},
		"XCWD": commandCwd{},
		"XMKD": commandMkd{},
		"XPWD": commandPwd{},
		"XRMD": commandRmd{},
	}
)

// commandAbor responds to the ABOR FTP command.
//
// Aborts previous FTP command.
type commandAbor struct{}

func (cmd commandAbor) RequireParam() bool {
	return false
}

func (cmd commandAbor) RequireAuth() bool {
	return false
}

func (cmd commandAbor) Async() bool {
	return true
}

func (cmd commandAbor) Execute(conn *ftpConn, param string) {
	conn.writeMessage(200, "OK")
}

// commandAllo responds to the ALLO FTP command.
//
// This is essentially a ping from the client so we just respond with an
// basic OK message.
type commandAllo struct{}

func (cmd commandAllo) RequireParam() bool {
	return false
}

func (cmd commandAllo) RequireAuth() bool {
	return false
}

func (cmd commandAllo) Async() bool {
	return true
}

func (cmd commandAllo) Execute(conn *ftpConn, param string) {
	conn.writeMessage(202, "Obsolete")
}

// commandAuth responds to the AUTH FTP command.
//
// Set up secure control channel.
type commandAuth struct{}

func (cmd commandAuth) RequireParam() bool {
	return true
}

func (cmd commandAuth) RequireAuth() bool {
	return false
}

func (cmd commandAuth) Async() bool {
	return false
}

func (cmd commandAuth) Execute(conn *ftpConn, param string) {
	if conn.usingTls {
		conn.writeMessage(503, "Already using TLS.")
		return
	}

	if !conn.canStartTls() {
		conn.writeMessage(500, "Command not found")
		return
	}

	upper := strings.ToUpper(param)

	if upper == "TLS" || upper == "TLS-C" || upper == "SSL" || upper == "TLS-P" {
		conn.writeMessage(234, fmt.Sprintf("AUTH %s successful.", param))

		conn.startTls()
	} else {
		conn.writeMessage(502, "Unrecognized encryption type (use TLS or SSL).")
	}
}

// commandCdup responds to the CDUP FTP command.
//
// Allows the client change their current directory to the parent.
type commandCdup struct{}

func (cmd commandCdup) RequireParam() bool {
	return false
}

func (cmd commandCdup) RequireAuth() bool {
	return true
}

func (cmd commandCdup) Async() bool {
	return true
}

func (cmd commandCdup) Execute(conn *ftpConn, param string) {
	otherCmd := &commandCwd{}
	otherCmd.Execute(conn, "..")
}

// commandCwd responds to the CWD FTP command. It allows the client to change the
// current working directory.
type commandCwd struct{}

func (cmd commandCwd) RequireParam() bool {
	return true
}

func (cmd commandCwd) RequireAuth() bool {
	return true
}

func (cmd commandCwd) Async() bool {
	return true
}

func (cmd commandCwd) Execute(conn *ftpConn, param string) {
	path := conn.buildPath(param)
	if conn.driver.ChangeDir(path) {
		conn.namePrefix = path
		conn.writeMessage(250, "Directory changed to "+path)
	} else {
		conn.writeMessage(550, "Action not taken")
	}
}

// commandDele responds to the DELE FTP command. It allows the client to delete
// a file
type commandDele struct{}

func (cmd commandDele) RequireParam() bool {
	return true
}

func (cmd commandDele) RequireAuth() bool {
	return true
}

func (cmd commandDele) Async() bool {
	return true
}

func (cmd commandDele) Execute(conn *ftpConn, param string) {
	path := conn.buildPath(param)
	if conn.driver.DeleteFile(path) {
		conn.writeMessage(250, "File deleted")
	} else {
		conn.writeMessage(550, "Action not taken")
	}
}

// commandEprt responds to the EPRT FTP command. It allows the client to
// request an active data socket with more options than the original PORT
// command. It mainly adds ipv6 support.
type commandEprt struct{}

func (cmd commandEprt) RequireParam() bool {
	return true
}

func (cmd commandEprt) RequireAuth() bool {
	return true
}

func (cmd commandEprt) Async() bool {
	return true
}

func (cmd commandEprt) Execute(conn *ftpConn, param string) {
	conn.restPosition = 0

	delim := string(param[0:1])
	parts := strings.Split(param, delim)
	addressFamily, err := strconv.Atoi(parts[1])
	host := parts[2]
	port, err := strconv.Atoi(parts[3])

	if addressFamily != 1 && addressFamily != 2 {
		conn.writeMessage(522, "Network protocol not supported, use (1,2)")
		return
	}

	_, err = conn.newActiveSocket(host, port)

	if err != nil {
		conn.writeMessage(425, "Data connection failed")
		return
	}

	conn.writeMessage(200, fmt.Sprintf("Connection established (%d)", port))
}

// commandEpsv responds to the EPSV FTP command. It allows the client to
// request a passive data socket with more options than the original PASV
// command. It mainly adds ipv6 support, although we don't support that yet.
type commandEpsv struct{}

func (cmd commandEpsv) RequireParam() bool {
	return false
}

func (cmd commandEpsv) RequireAuth() bool {
	return true
}

func (cmd commandEpsv) Async() bool {
	return true
}

func (cmd commandEpsv) Execute(conn *ftpConn, param string) {
	conn.restPosition = 0

	socket, err := conn.newPassiveSocket()
	if err != nil {
		conn.writeMessage(425, "Data connection failed")
		return
	}
	msg := fmt.Sprintf("Entering Extended Passive Mode (|||%d|)", socket.Port())
	conn.writeMessage(229, msg)
}

// commandFeat responds to the FEAT FTP command.
//
// List all new features supported as defined in RFC-2398.
type commandFeat struct{}

func (cmd commandFeat) RequireParam() bool {
	return false
}

func (cmd commandFeat) RequireAuth() bool {
	return false
}

func (cmd commandFeat) Async() bool {
	return true
}

func (cmd commandFeat) Execute(conn *ftpConn, param string) {
	conn.writeLines(211,
		"211-Features supported:",
		" AUTH TLS",
		" AUTH SSL",
		" EPRT",
		" EPSV",
		" MDTM",
		" PBSZ",
		" PROT",
		" SIZE",
		" UTF8",
		"211 End FEAT.",
	)
}

// commandList responds to the LIST FTP command. It allows the client to retreive
// a detailed listing of the contents of a directory.
type commandList struct{}

func (cmd commandList) RequireParam() bool {
	return false
}

func (cmd commandList) RequireAuth() bool {
	return true
}

func (cmd commandList) Async() bool {
	return true
}

func (cmd commandList) Execute(conn *ftpConn, param string) {
	path := conn.buildPath(param)
	if files, ok := conn.driver.DirContents(path); ok {
		formatter := newListFormatter(files)
		conn.sendOutofbandData(formatter.Detailed())
	} else {
		conn.writeMessage(450, "File not available")
	}
}

// commandNlst responds to the NLST FTP command. It allows the client to
// retreive a list of filenames in the current directory.
type commandNlst struct{}

func (cmd commandNlst) RequireParam() bool {
	return false
}

func (cmd commandNlst) RequireAuth() bool {
	return true
}

func (cmd commandNlst) Async() bool {
	return true
}

func (cmd commandNlst) Execute(conn *ftpConn, param string) {
	path := conn.buildPath(param)
	if files, ok := conn.driver.DirContents(path); ok {
		formatter := newListFormatter(files)
		conn.sendOutofbandData(formatter.Short())
	} else {
		conn.writeMessage(450, "File not available")
	}
}

// commandMdtm responds to the MDTM FTP command. It allows the client to
// retreive the last modified time of a file.
type commandMdtm struct{}

func (cmd commandMdtm) RequireParam() bool {
	return true
}

func (cmd commandMdtm) RequireAuth() bool {
	return true
}

func (cmd commandMdtm) Async() bool {
	return true
}

func (cmd commandMdtm) Execute(conn *ftpConn, param string) {
	path := conn.buildPath(param)
	if time, ok := conn.driver.ModifiedTime(path); ok {
		conn.writeMessage(213, strftime.Format("%Y%m%d%H%M%S", time))
	} else {
		conn.writeMessage(450, "File not available")
	}
}

// commandMkd responds to the MKD FTP command. It allows the client to create
// a new directory
type commandMkd struct{}

func (cmd commandMkd) RequireParam() bool {
	return true
}

func (cmd commandMkd) RequireAuth() bool {
	return true
}

func (cmd commandMkd) Async() bool {
	return true
}

func (cmd commandMkd) Execute(conn *ftpConn, param string) {
	path := conn.buildPath(param)
	if conn.driver.MakeDir(path) {
		conn.writeMessage(257, "Directory created")
	} else {
		conn.writeMessage(550, "Action not taken")
	}
}

// commandMode responds to the MODE FTP command.
//
// the original FTP spec had various options for hosts to negotiate how data
// would be sent over the data socket, In reality these days (S)tream mode
// is all that is used for the mode - data is just streamed down the data
// socket unchanged.
type commandMode struct{}

func (cmd commandMode) RequireParam() bool {
	return true
}

func (cmd commandMode) RequireAuth() bool {
	return true
}

func (cmd commandMode) Async() bool {
	return true
}

func (cmd commandMode) Execute(conn *ftpConn, param string) {
	if strings.ToUpper(param) == "S" {
		conn.writeMessage(200, "OK")
	} else {
		conn.writeMessage(504, "MODE is an obsolete command")
	}
}

// commandNoop responds to the NOOP FTP command.
//
// This is essentially a ping from the client so we just respond with an
// basic 200 message.
type commandNoop struct{}

func (cmd commandNoop) RequireParam() bool {
	return false
}

func (cmd commandNoop) RequireAuth() bool {
	return false
}

func (cmd commandNoop) Async() bool {
	return true
}

func (cmd commandNoop) Execute(conn *ftpConn, param string) {
	conn.writeMessage(200, "OK")
}

// commandOpts responds to the OPTS FTP command.
//
// This is essentially a ping from the client so we just respond with an
// basic 200 message.
type commandOpts struct{}

func (cmd commandOpts) RequireParam() bool {
	return false
}

func (cmd commandOpts) RequireAuth() bool {
	return true
}

func (cmd commandOpts) Async() bool {
	return true
}

func (cmd commandOpts) Execute(conn *ftpConn, param string) {
	upper := strings.ToUpper(param)

	if upper == "UTF8 ON" || upper == "UTF8" {
		conn.writeMessage(200, "OK")
		return
	}

	conn.writeMessage(500, "Command not found")
}

// commandPass respond to the PASS FTP command by asking the driver if the
// supplied username and password are valid
type commandPass struct{}

func (cmd commandPass) RequireParam() bool {
	return true
}

func (cmd commandPass) RequireAuth() bool {
	return false
}

func (cmd commandPass) Async() bool {
	return true
}

func (cmd commandPass) Execute(conn *ftpConn, param string) {
	if conn.driver.Authenticate(conn.reqUser, param) {
		conn.user = conn.reqUser
		conn.reqUser = ""
		conn.writeMessage(230, "Password ok, continue")
	} else {
		conn.writeMessage(530, "Incorrect password, not logged in")
	}
}

// commandPasv responds to the PASV FTP command.
//
// The client is requesting us to open a new TCP listing socket and wait for them
// to connect to it.
type commandPasv struct{}

func (cmd commandPasv) RequireParam() bool {
	return false
}

func (cmd commandPasv) RequireAuth() bool {
	return true
}

func (cmd commandPasv) Async() bool {
	return true
}

func (cmd commandPasv) Execute(conn *ftpConn, param string) {
	conn.restPosition = 0

	socket, err := conn.newPassiveSocket()
	if err != nil {
		conn.writeMessage(425, "Data connection failed")
		return
	}

	p1 := socket.Port() / 256
	p2 := socket.Port() - (p1 * 256)

	host := conn.passiveOpts.NatAddress

	if host == "" {
		host = socket.Host()
	}

	quads := strings.Split(host, ".")
	target := fmt.Sprintf("(%s,%s,%s,%s,%d,%d)", quads[0], quads[1], quads[2], quads[3], p1, p2)
	msg := "Entering Passive Mode " + target
	conn.writeMessage(227, msg)
}

// commandPbsz responds to the PBSZ FTP command.
//
// Negotiate size of buffer for secure data transfer.
// For TLS/SSL the only valid value for the parameter is '0'.
// Any other value is accepted but ignored.
type commandPbsz struct{}

func (cmd commandPbsz) RequireParam() bool {
	return false
}

func (cmd commandPbsz) RequireAuth() bool {
	return false
}

func (cmd commandPbsz) Async() bool {
	return true
}

func (cmd commandPbsz) Execute(conn *ftpConn, param string) {
	if conn.usingTls {
		conn.writeMessage(200, "PBSZ=0 successful.")
		conn.usingPbsz = true
	} else {
		conn.writeMessage(503, "PBSZ not allowed on insecure control connection.")
	}
}

// commandPort responds to the PORT FTP command.
//
// The client has opened a listening socket for sending out of band data and
// is requesting that we connect to it
type commandPort struct{}

func (cmd commandPort) RequireParam() bool {
	return true
}

func (cmd commandPort) RequireAuth() bool {
	return true
}

func (cmd commandPort) Async() bool {
	return true
}

func (cmd commandPort) Execute(conn *ftpConn, param string) {
	conn.restPosition = 0

	nums := strings.Split(param, ",")
	portOne, _ := strconv.Atoi(nums[4])
	portTwo, _ := strconv.Atoi(nums[5])
	port := (portOne * 256) + portTwo
	host := nums[0] + "." + nums[1] + "." + nums[2] + "." + nums[3]

	_, err := conn.newActiveSocket(host, port)

	if err != nil {
		conn.writeMessage(425, "Data connection failed")
		return
	}

	conn.writeMessage(200, fmt.Sprintf("Connection established (%d)", port))
}

// commandProt responds to the PROT FTP command.
//
// Setup un/secure data channel.
type commandProt struct{}

func (cmd commandProt) RequireParam() bool {
	return false
}

func (cmd commandProt) RequireAuth() bool {
	return false
}

func (cmd commandProt) Async() bool {
	return true
}

func (cmd commandProt) Execute(conn *ftpConn, param string) {
	upper := strings.ToUpper(param)

	if !conn.usingTls {
		conn.writeMessage(503, "PROT not allowed on insecure control connection.")
	} else if !conn.usingPbsz {
		conn.writeMessage(503, "You must issue the PBSZ command prior to PROT.")
	} else if upper == "C" {
		conn.writeMessage(200, "Protection set to Clear")
	} else if upper == "P" {
		conn.writeMessage(200, "Protection set to Private")
		conn.usingProt = true
	} else if upper == "S" || upper == "E" {
		conn.writeMessage(521, fmt.Sprintf("PROT %s unsupported (use C or P).", param))
	} else {
		conn.writeMessage(502, "Unrecognized PROT type (use C or P).")
	}
}

// commandPwd responds to the PWD FTP command.
//
// Tells the client what the current working directory is.
type commandPwd struct{}

func (cmd commandPwd) RequireParam() bool {
	return false
}

func (cmd commandPwd) RequireAuth() bool {
	return true
}

func (cmd commandPwd) Async() bool {
	return true
}

func (cmd commandPwd) Execute(conn *ftpConn, param string) {
	conn.writeMessage(257, "\""+conn.namePrefix+"\" is the current directory")
}

// CommandQuit responds to the QUIT FTP command. The client has requested the
// connection be closed.
type commandQuit struct{}

func (cmd commandQuit) RequireParam() bool {
	return false
}

func (cmd commandQuit) RequireAuth() bool {
	return false
}

func (cmd commandQuit) Async() bool {
	return true
}

func (cmd commandQuit) Execute(conn *ftpConn, param string) {
	conn.writeMessage(221, "Goodbye.")
	conn.Close()
}

// commandRest responds to the REST FTP command. It allows the client to
// resume file download.
type commandRest struct{}

func (cmd commandRest) RequireParam() bool {
	return true
}

func (cmd commandRest) RequireAuth() bool {
	return true
}

func (cmd commandRest) Async() bool {
	return true
}

func (cmd commandRest) Execute(conn *ftpConn, param string) {
	position, err := strconv.ParseInt(param, 10, 64)

	if err != nil || position < 0 {
		conn.writeMessage(500, "Invalid parameter")
		return
	}

	conn.restPosition = position

	conn.writeMessage(350, "Requested file action pending further information")
}

// commandRetr responds to the RETR FTP command. It allows the client to
// download a file.
type commandRetr struct{}

func (cmd commandRetr) RequireParam() bool {
	return true
}

func (cmd commandRetr) RequireAuth() bool {
	return true
}

func (cmd commandRetr) Async() bool {
	return true
}

func (cmd commandRetr) Execute(conn *ftpConn, param string) {
	path := conn.buildPath(param)

	if reader, ok := conn.driver.GetFile(path, conn.restPosition); ok {
		defer reader.Close()

		conn.sendOutofbandReader(reader)
	} else {
		conn.writeMessage(551, "File not available")
	}
}

// commandRnfr responds to the RNFR FTP command. It's the first of two commands
// required for a client to rename a file.
type commandRnfr struct{}

func (cmd commandRnfr) RequireParam() bool {
	return true
}

func (cmd commandRnfr) RequireAuth() bool {
	return true
}

func (cmd commandRnfr) Async() bool {
	return true
}

func (cmd commandRnfr) Execute(conn *ftpConn, param string) {
	conn.renameFrom = conn.buildPath(param)
	conn.writeMessage(350, "Requested file action pending further information.")
}

// commandRnto responds to the RNTO FTP command. It's the second of two commands
// required for a client to rename a file.
type commandRnto struct{}

func (cmd commandRnto) RequireParam() bool {
	return true
}

func (cmd commandRnto) RequireAuth() bool {
	return true
}

func (cmd commandRnto) Async() bool {
	return true
}

func (cmd commandRnto) Execute(conn *ftpConn, param string) {
	toPath := conn.buildPath(param)
	if conn.driver.Rename(conn.renameFrom, toPath) {
		conn.writeMessage(250, "File renamed")
	} else {
		conn.writeMessage(550, "Action not taken")
	}
}

// commandRmd responds to the RMD FTP command. It allows the client to delete a
// directory.
type commandRmd struct{}

func (cmd commandRmd) RequireParam() bool {
	return true
}

func (cmd commandRmd) RequireAuth() bool {
	return true
}

func (cmd commandRmd) Async() bool {
	return true
}

func (cmd commandRmd) Execute(conn *ftpConn, param string) {
	path := conn.buildPath(param)
	if conn.driver.DeleteDir(path) {
		conn.writeMessage(250, "Directory deleted")
	} else {
		conn.writeMessage(550, "Action not taken")
	}
}

// commandSize responds to the SIZE FTP command. It returns the size of the
// requested path in bytes.
type commandSize struct{}

func (cmd commandSize) RequireParam() bool {
	return true
}

func (cmd commandSize) RequireAuth() bool {
	return true
}

func (cmd commandSize) Async() bool {
	return true
}

func (cmd commandSize) Execute(conn *ftpConn, param string) {
	path := conn.buildPath(param)
	bytes := conn.driver.Bytes(path)
	if bytes >= 0 {
		conn.writeMessage(213, fmt.Sprintf("%d", bytes))
	} else {
		conn.writeMessage(450, "file not available")
	}
}

// commandStor responds to the STOR FTP command. It allows the user to upload a
// new file.
type commandStor struct{}

func (cmd commandStor) RequireParam() bool {
	return true
}

func (cmd commandStor) RequireAuth() bool {
	return true
}

func (cmd commandStor) Async() bool {
	return true
}

func (cmd commandStor) Execute(conn *ftpConn, param string) {
	targetPath := conn.buildPath(param)

	if !conn.DataConnWait(10 * time.Second) {
		conn.writeMessage(425, "Can't open data connection.")
		return
	}

	reader := ioutils.NewStartReader(conn.dataConn, func() {
		conn.writeMessage(150, "Data transfer starting")
	})

	if ok := conn.driver.PutFile(targetPath, reader); ok {
		conn.writeMessage(226, "Transfer complete.")
	} else {
		conn.writeMessage(450, "error during transfer")
		return
	}
}

// commandStru responds to the STRU FTP command.
//
// like the MODE and TYPE commands, stru[cture] dates back to a time when the
// FTP protocol was more aware of the content of the files it was transferring,
// and would sometimes be expected to translate things like EOL markers on the
// fly.
//
// These days files are sent unmodified, and F(ile) mode is the only one we
// really need to support.
type commandStru struct{}

func (cmd commandStru) RequireParam() bool {
	return true
}

func (cmd commandStru) RequireAuth() bool {
	return true
}

func (cmd commandStru) Async() bool {
	return true
}

func (cmd commandStru) Execute(conn *ftpConn, param string) {
	if strings.ToUpper(param) == "F" {
		conn.writeMessage(200, "OK")
	} else {
		conn.writeMessage(504, "STRU is an obsolete command")
	}
}

// commandSyst responds to the SYST FTP command by providing a canned response.
type commandSyst struct{}

func (cmd commandSyst) RequireParam() bool {
	return false
}

func (cmd commandSyst) RequireAuth() bool {
	return true
}

func (cmd commandSyst) Async() bool {
	return true
}

func (cmd commandSyst) Execute(conn *ftpConn, param string) {
	conn.writeMessage(215, "UNIX Type: L8")
}

// commandType responds to the TYPE FTP command.
//
//  like the MODE and STRU commands, TYPE dates back to a time when the FTP
//  protocol was more aware of the content of the files it was transferring, and
//  would sometimes be expected to translate things like EOL markers on the fly.
//
//  Valid options were A(SCII), I(mage), E(BCDIC) or LN (for local type). Since
//  we plan to just accept bytes from the client unchanged, I think Image mode is
//  adequate. The RFC requires we accept ASCII mode however, so accept it, but
//  ignore it.
type commandType struct{}

func (cmd commandType) RequireParam() bool {
	return false
}

func (cmd commandType) RequireAuth() bool {
	return true
}

func (cmd commandType) Async() bool {
	return true
}

func (cmd commandType) Execute(conn *ftpConn, param string) {
	upper := strings.ToUpper(param)

	if upper == "A" {
		conn.writeMessage(200, "Type set to ASCII")
	} else if upper == "I" {
		conn.writeMessage(200, "Type set to binary")
	} else {
		conn.writeMessage(500, "Invalid type")
	}
}

// commandUser responds to the USER FTP command by asking for the password
type commandUser struct{}

func (cmd commandUser) RequireParam() bool {
	return true
}

func (cmd commandUser) RequireAuth() bool {
	return false
}

func (cmd commandUser) Async() bool {
	return true
}

func (cmd commandUser) Execute(conn *ftpConn, param string) {
	if !conn.usingTls && conn.cryptoConfig.Force {
		conn.writeMessage(534, "Policy Requires SSL")
	} else {
		conn.reqUser = param
		conn.writeMessage(331, "User name ok, password required")
	}
}

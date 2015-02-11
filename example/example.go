package main

import (
	"github.com/koofr/graval"
	"github.com/koofr/graval/memory"
	"log"
)

func main() {
	host := "127.0.0.1"
	port := 8021
	username := "test"
	password := "test"

	files := map[string]*memory.MemoryFile{
		"/": &memory.MemoryFile{graval.NewDirItem(""), nil},
	}

	factory := &memory.MemoryDriverFactory{files, username, password}

	server := graval.NewFTPServer(&graval.FTPServerOpts{
		ServerName: "Example FTP server",
		Factory:    factory,
		Hostname:   host,
		Port:       port,
		PassiveOpts: &graval.PassiveOpts{
			ListenAddress: host,
			NatAddress:    host,
			PassivePorts: &graval.PassivePorts{
				Low:  42000,
				High: 45000,
			},
		},
	})

	log.Printf("Example FTP server listening on %s:%d", host, port)
	log.Printf("Access: ftp://%s:%s@%s:%d/", username, password, host, port)

	err := server.ListenAndServe()

	if err != nil {
		log.Fatal(err)
	}
}

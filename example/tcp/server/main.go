package main

import (
	"bufio"
	"flag"
	"github.com/zeroFruit/thttps/pkg/tls"
	"log"
	"net"
)

var (
	certFile = flag.String("certfile", "server.crt", "Certification")
	keyFile  = flag.String("keyfile", "server.key", "Key file")
	port     = flag.String("port", ":443", "HTTPS server port")
)

func main() {
	log.SetFlags(log.Lshortfile)
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Println(err)
		return
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	lis, err := tls.Listen("tcp", *port, config)
	if err != nil {
		log.Println(err)
		return
	}
	defer lis.Close()

	for {
		log.Println("listening...")
		conn, err := lis.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		msg, err := r.ReadString('\n')
		if err != nil {
			log.Println(err)
			return
		}

		println(msg)

		n, err := conn.Write([]byte("world\n"))
		if err != nil {
			log.Println(n, err)
			return
		}
	}
}

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/zeroFruit/thttps"
)

var (
	certFile = flag.String("certfile", "cert.pem", "Certification")
	keyFile  = flag.String("keyfile", "key.pem", "Key file")
	port     = flag.String("port", ":443", "HTTPS server port")
)

func main() {
	log.SetFlags(log.Lshortfile)
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("world\n"))
	})

	log.Println(fmt.Sprintf("Listening on %s", *port))
	if err := thttps.Listen(*port, *certFile, *keyFile, mux); err != nil {
		log.Println(err)
	}
}

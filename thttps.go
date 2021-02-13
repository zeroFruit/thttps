package thttps

import (
	"net/http"

	"github.com/zeroFruit/thttps/pkg/tls"
)

func Listen(addr, certFile, keyFile string, handler http.Handler) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	lis, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return err
	}
	defer lis.Close()

	srv := &http.Server{Handler: handler}
	return srv.Serve(lis)
}

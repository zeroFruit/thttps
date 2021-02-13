# thttps

Basic TLS implementation in Go, written as a learning project. Most components are forked from Go version 1.7

tiny-HTTPS is not suitable for real-world use, but may be of interest to others learning about TLS basic, including:

- Basic handshaking with no extentions (SNI, ALPN ...)
- Data transfer and validate encrypted message with MAC for data integrity 



## Usage

Before installing package, you need to generate private key for your server.

```
openssl genrsa -out key.pem 2048
```

Then generate self-signed certificate for the test.

```
openssl req -new -x509 -sha256 -key key.pem -out cert.pem -days 3650 -subj "/C=KR/ST=Seoul/L=Seoul/O=Global Security/OU=IT Department/CN=*"
```



To install ttls package, you need to install Go and set your Go workspace first.

1. The first need [Go](https://golang.org/) installed (**version 1.12+ is required**), then you can use the below Go command to install ttls.

   ```
   $ go get -u github.com/zeroFruit/thttps
   ```

2. Configure your HTTPS server code on `server.go`  (private key, certificate files must be on the same directory)

   ```go
   package main
   
   import (
   	"log"
   	"net/http"
   
   	"github.com/zeroFruit/thttps"
   )
   
   func main() {
   	mux := http.NewServeMux()
   	mux.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
   		w.Header().Set("Content-Type", "text/plain")
   		w.Write([]byte("world\n"))
   	})
   
       log.Fatal(https.Listen(":8443", "cert.pem", "key.pem", mux))
   }
   ```

3. Run your server

   ```
   $ go run server.go
   ```

4. Using curl you can send HTTP request on your server

   ```
   $ curl --insecure https://localhost:8443/hello
   world
   ```

   

## Architecture 

If you want to see how codes are sturctured or want to see bird-eye view of this package. You can find these on the [ARCHITECTURE.md](./docs/ARCHITECTURE.md).



## Blog Post

If you are not familiar with the SSL/TLS protocols "and" familiar with Korean, you can find the blog post which shows how SSL/TLS protocol works.
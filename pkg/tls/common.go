// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	VersionTLS12 = 0x0303
)

const (
	maxPlaintext    = 16384        // maximum plaintext payload length
	maxCiphertext   = 16384 + 2048 // maximum ciphertext payload length
	recordHeaderLen = 5            // record header length
	maxHandshake    = 65536        // maximum handshake we support (protocol max is 16 MB)
)

// TLS record types.
type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// TLS handshake message types.
const (
	typeClientHello       uint8 = 1
	typeServerHello       uint8 = 2
	typeCertificate       uint8 = 11
	typeServerHelloDone   uint8 = 14
	typeClientKeyExchange uint8 = 16
	typeFinished          uint8 = 20
)

// TLS compression types.
const (
	compressionNone uint8 = 0
)

// Hash functions for TLS 1.2 (See RFC 5246, section A.4.1)
const (
	hashSHA1   uint8 = 2
	hashSHA256 uint8 = 4
	hashSHA384 uint8 = 5
)

// signatureAndHash mirrors the TLS 1.2, SignatureAndHashAlgorithm struct. See
// RFC 5246, section A.4.1.
type signatureAndHash struct {
	hash, signature uint8
}

// ConnectionState records basic TLS details about the connection.
type ConnectionState struct {
	Version           uint16                // TLS version used by the connection (e.g. VersionTLS12)
	HandshakeComplete bool                  // TLS handshake is complete
	CipherSuite       uint16                // cipher suite in use (TLS_RSA_WITH_RC4_128_SHA, ...)
	ServerName        string                // server name requested by client, if any (server side only)
	VerifiedChains    [][]*x509.Certificate // verified chains built from PeerCertificates
}

// A Config structure is used to configure a TLS client or server.
// After one has been passed to a TLS function it must not be
// modified. A Config may be reused; the tls package will also not
// modify it.
type Config struct {
	// Rand provides the source of entropy for nonces and RSA blinding.
	// If Rand is nil, TLS uses the cryptographic random reader in package
	// crypto/rand.
	// The Reader must be safe for use by multiple goroutines.
	Rand io.Reader

	// Time returns the current time as the number of seconds since the epoch.
	// If Time is nil, TLS uses time.Now.
	Time func() time.Time

	// Certificates contains one or more certificate chains
	// to present to the other side of the connection.
	// Server configurations must include at least one certificate
	// or else set GetCertificate.
	Certificates []Certificate

	// RootCAs defines the set of root certificate authorities
	// that clients use when verifying server certificates.
	// If RootCAs is nil, TLS uses the host's root CA set.
	RootCAs *x509.CertPool

	// ServerName is used to verify the hostname on the returned
	// certificates.
	ServerName string

	// CipherSuites is a list of supported cipher suites. If CipherSuites
	// is nil, TLS uses a list of suites supported by the implementation.
	CipherSuites []uint16

	// mutex protects sessionTicketKeys
	mutex sync.RWMutex
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

func (c *Config) cipherSuites() []uint16 {
	s := c.CipherSuites
	if s == nil {
		s = defaultCipherSuites()
	}
	return s
}

// getCertificate returns the best certificate,
// defaulting to the first element of c.Certificates.
func (c *Config) getCertificate() *Certificate {
	// return the first certificate.
	return &c.Certificates[0]
}

// A Certificate is a chain of one or more certificates, leaf first.
type Certificate struct {
	Certificate [][]byte
	// PrivateKey contains the private key corresponding to the public key
	// in Leaf. For a server, this must implement crypto.Signer and/or
	// crypto.Decrypter, with an RSA.
	PrivateKey crypto.PrivateKey
	// Leaf is the parsed form of the leaf certificate, which may be
	// initialized using x509.ParseCertificate to reduce per-handshake
	// processing for TLS clients doing client authentication. If nil, the
	// leaf certificate will be parsed as needed.
	Leaf *x509.Certificate
}

type handshakeMessage interface {
	marshal() []byte
	unmarshal([]byte) bool
}

var emptyConfig Config

func defaultConfig() *Config {
	return &emptyConfig
}

var (
	once                   sync.Once
	varDefaultCipherSuites []uint16
)

func defaultCipherSuites() []uint16 {
	once.Do(initDefaultCipherSuites)
	return varDefaultCipherSuites
}

func initDefaultCipherSuites() {
	varDefaultCipherSuites = make([]uint16, 0, len(cipherSuites))
	for _, suite := range cipherSuites {
		varDefaultCipherSuites = append(varDefaultCipherSuites, suite.id)
	}
}

func unexpectedMessageError(wanted, got interface{}) error {
	return fmt.Errorf("tls: received unexpected handshake message of type %T when waiting for %T", got, wanted)
}

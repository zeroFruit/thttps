// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
)

type clientHandshakeState struct {
	c            *Conn
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
}

func (c *Conn) clientHandshake() error {
	if c.config == nil {
		c.config = defaultConfig()
	}

	hello, err := c.sendClientHelloMsg()
	if err != nil {
		return err
	}
	serverHello, err := c.waitServerHelloMsg()
	if err != nil {
		return err
	}

	c.vers = VersionTLS12
	c.haveVers = true

	suite := mutualCipherSuite(hello.cipherSuites, serverHello.cipherSuite)
	if suite == nil {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}

	hs := &clientHandshakeState{
		c:            c,
		serverHello:  serverHello,
		hello:        hello,
		suite:        suite,
		finishedHash: newFinishedHash(c.vers),
	}

	hs.finishedHash.Write(hs.hello.marshal())
	hs.finishedHash.Write(hs.serverHello.marshal())

	if err := hs.doFullHandshake(); err != nil {
		return err
	}
	if err := hs.establishKeys(); err != nil {
		return err
	}
	if err := hs.sendFinished(c.firstFinished[:]); err != nil {
		return err
	}
	if err := hs.readFinished(nil); err != nil {
		return err
	}

	c.handshakeComplete = true
	c.cipherSuite = suite.id
	return nil
}

func (c *Conn) sendClientHelloMsg() (*clientHelloMsg, error) {
	hello := &clientHelloMsg{
		vers:               VersionTLS12,
		compressionMethods: []uint8{compressionNone},
		random:             make([]byte, 32),
	}

	possibleCipherSuites := c.config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

NextCipherSuite:
	for _, suiteId := range possibleCipherSuites {
		for _, suite := range cipherSuites {
			if suite.id != suiteId {
				continue
			}
			hello.cipherSuites = append(hello.cipherSuites, suiteId)
			continue NextCipherSuite
		}
	}

	_, err := io.ReadFull(c.config.rand(), hello.random)
	if err != nil {
		c.sendAlert(alertInternalError)
		return nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	_, err = c.writeRecord(recordTypeHandshake, hello.marshal())
	return hello, err
}

func (c *Conn) waitServerHelloMsg() (*serverHelloMsg, error) {
	msg, err := c.readHandshake()
	if err != nil {
		return nil, err
	}
	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, unexpectedMessageError(serverHello, msg)
	}
	return serverHello, nil
}

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	certMsg, err := hs.waitCertificateMsg()
	hs.finishedHash.Write(certMsg.marshal())

	certs, err := hs.verifyServer(certMsg.certificates)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	switch certs[0].PublicKey.(type) {
	case *rsa.PublicKey:
		break
	default:
		c.sendAlert(alertUnsupportedCertificate)
		return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
	}

	shd, err := hs.waitServerHelloDoneMsg()
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	hs.finishedHash.Write(shd.marshal())

	//preMasterSecret, ckx, err := hs.suite.ka(c.vers).generateClientKeyExchange(c.config, hs.hello, certs[0])
	//if err != nil {
	//	c.sendAlert(alertInternalError)
	//	return err
	//}
	//if ckx == nil {
	//	c.sendAlert(alertInternalError)
	//	return errors.New("tls: unexpected ServerKeyExchange")
	//}
	//hs.finishedHash.Write(ckx.marshal())
	//// send clientKeyExchangeMsg message
	//c.writeRecord(recordTypeHandshake, ckx.marshal())

	preMasterSecret, err := hs.sendClientKeyExchangeMsg(certs[0])
	if err != nil {
		return err
	}

	hs.masterSecret = masterFromPreMasterSecret(c.vers, preMasterSecret, hs.hello.random, hs.serverHello.random)
	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *clientHandshakeState) waitCertificateMsg() (*certificateMsg, error) {
	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return nil, err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		c.sendAlert(alertUnexpectedMessage)
		return nil, unexpectedMessageError(certMsg, msg)
	}
	return certMsg, nil
}
func (hs *clientHandshakeState) waitServerHelloDoneMsg() (*serverHelloDoneMsg, error) {
	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return nil, err
	}
	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, unexpectedMessageError(shd, msg)
	}
	return shd, nil
}

// verifyServer verifies server with the given certificates
func (hs *clientHandshakeState) verifyServer(certificates [][]byte) ([]*x509.Certificate, error) {
	c := hs.c

	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, errors.New("tls: failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}

	opts := x509.VerifyOptions{
		Roots:         c.config.RootCAs,
		CurrentTime:   c.config.time(),
		DNSName:       c.config.ServerName,
		Intermediates: x509.NewCertPool(),
	}

	for i, cert := range certs {
		if i == 0 {
			continue
		}
		opts.Intermediates.AddCert(cert)
	}
	var err error
	c.verifiedChains, err = certs[0].Verify(opts)
	if err != nil {
		// NOTE: just left log, then proceed
		fmt.Printf("failed to verify server. %s\n", err)
	}
	return certs, nil
}

func (hs *clientHandshakeState) sendClientKeyExchangeMsg(cert *x509.Certificate) ([]byte, error) {
	c := hs.c

	preMasterSecret, ckx, err := hs.suite.ka(c.vers).generateClientKeyExchange(c.config, hs.hello, cert)
	if err != nil {
		c.sendAlert(alertInternalError)
		return nil, err
	}
	if ckx == nil {
		c.sendAlert(alertInternalError)
		return nil, errors.New("tls: unexpected ServerKeyExchange")
	}
	hs.finishedHash.Write(ckx.marshal())
	// send clientKeyExchangeMsg message
	c.writeRecord(recordTypeHandshake, ckx.marshal())
	return preMasterSecret, nil
}

// establishKeys create MAC auth key, encrypt key
func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction

	clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
	clientHash = hs.suite.mac(c.vers, clientMAC)
	serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
	serverHash = hs.suite.mac(c.vers, serverMAC)

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeState) readFinished(out []byte) error {
	c := hs.c

	c.readRecord(recordTypeChangeCipherSpec)
	if err := c.in.error(); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server's Finished message was incorrect")
	}
	hs.finishedHash.Write(serverFinished.marshal())
	copy(out, verify)
	return nil
}

func (hs *clientHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	c.writeRecord(recordTypeChangeCipherSpec, []byte{1})

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	c.writeRecord(recordTypeHandshake, finished.marshal())
	copy(out, finished.verifyData)
	return nil
}

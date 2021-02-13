// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

// serverHandshakeState contains details of a server handshake in progress.
// It's discarded once the handshake has completed.
type serverHandshakeState struct {
	c               *Conn
	clientHello     *clientHelloMsg
	hello           *serverHelloMsg
	suite           *cipherSuite
	rsaDecryptOk    bool
	rsaSignOk       bool
	finishedHash    finishedHash
	masterSecret    []byte
	certsFromClient [][]byte
	cert            *Certificate
}

// serverHandshake performs a TLS handshake as a server.
func (c *Conn) serverHandshake() error {
	hs := serverHandshakeState{
		c: c,
	}
	if err := hs.readClientHello(); err != nil {
		return err
	}

	if err := hs.doFullHandshake(); err != nil {
		return err
	}
	if err := hs.establishKeys(); err != nil {
		return err
	}
	if err := hs.readFinished(c.firstFinished[:]); err != nil {
		return err
	}
	if err := hs.sendFinished(nil); err != nil {
		return err
	}
	c.handshakeComplete = true

	return nil
}

// readClientHello reads a ClientHello message from the client.
func (hs *serverHandshakeState) readClientHello() error {
	config := hs.c.config
	c := hs.c

	ch, err := hs.waitClientHelloMsg()
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	hs.clientHello = ch
	c.vers = VersionTLS12
	c.haveVers = true

	hs.hello = new(serverHelloMsg)

	hs.hello.vers = c.vers
	// create server nonce
	hs.hello.random = make([]byte, 32)
	_, err = io.ReadFull(config.rand(), hs.hello.random)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	hs.hello.compressionMethod = compressionNone
	hs.cert = config.getCertificate()

	if priv, ok := hs.cert.PrivateKey.(crypto.Signer); ok {
		switch priv.Public().(type) {
		case *rsa.PublicKey:
			hs.rsaSignOk = true
		default:
			c.sendAlert(alertInternalError)
			return fmt.Errorf("crypto/tls: unsupported signing key type (%T)", priv.Public())
		}
	}
	if priv, ok := hs.cert.PrivateKey.(crypto.Decrypter); ok {
		switch priv.Public().(type) {
		case *rsa.PublicKey:
			hs.rsaDecryptOk = true
		default:
			c.sendAlert(alertInternalError)
			return fmt.Errorf("crypto/tls: unsupported decryption key type (%T)", priv.Public())
		}
	}

	preferenceList := hs.clientHello.cipherSuites
	supportedList := c.config.cipherSuites()
	for _, id := range preferenceList {
		if hs.setCipherSuite(id, supportedList, c.vers) {
			break
		}
	}
	if hs.suite == nil {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: no cipher suite supported by both client and server")
	}
	return nil
}

func (hs *serverHandshakeState) waitClientHelloMsg() (*clientHelloMsg, error) {
	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return nil, err
	}
	var ok bool
	ch, ok := msg.(*clientHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, unexpectedMessageError(hs.clientHello, msg)
	}
	return ch, nil
}

func (hs *serverHandshakeState) doFullHandshake() error {
	config := hs.c.config
	c := hs.c

	hs.hello.cipherSuite = hs.suite.id

	hs.finishedHash = newFinishedHash(hs.c.vers)
	hs.finishedHash.discardHandshakeBuffer()
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello.marshal())

	hs.sendServerHelloAndCert()

	helloDone := new(serverHelloDoneMsg)
	hs.finishedHash.Write(helloDone.marshal())

	c.writeRecord(recordTypeHandshake, helloDone.marshal())

	ckx, err := hs.waitClientKeyExchangeMsg()
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	hs.finishedHash.Write(ckx.marshal())

	preMasterSecret, err := hs.suite.ka(c.vers).processClientKeyExchange(config, hs.cert, ckx, c.vers)
	if err != nil {
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	hs.masterSecret = masterFromPreMasterSecret(c.vers, preMasterSecret, hs.clientHello.random, hs.hello.random)
	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *serverHandshakeState) waitClientKeyExchangeMsg() (*clientKeyExchangeMsg, error) {
	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return nil, err
	}
	// Get client key exchange
	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, unexpectedMessageError(ckx, msg)
	}
	return ckx, nil
}

// sendServerHelloAndCert sends server hello msg and certificate message to client
// all the message setup at readClientHello
func (hs *serverHandshakeState) sendServerHelloAndCert() {
	hs.c.writeRecord(recordTypeHandshake, hs.hello.marshal())

	certMsg := new(certificateMsg)
	certMsg.certificates = hs.cert.Certificate
	hs.finishedHash.Write(certMsg.marshal())
	hs.c.writeRecord(recordTypeHandshake, certMsg.marshal())
}

func (hs *serverHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.masterSecret, hs.clientHello.random, hs.hello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)

	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction

	clientCipher = hs.suite.cipher(clientKey, clientIV, true /* for reading */)
	clientHash = hs.suite.mac(c.vers, clientMAC)
	serverCipher = hs.suite.cipher(serverKey, serverIV, false /* not for reading */)
	serverHash = hs.suite.mac(c.vers, serverMAC)

	c.in.prepareCipherSpec(c.vers, clientCipher, clientHash)
	c.out.prepareCipherSpec(c.vers, serverCipher, serverHash)

	return nil
}

func (hs *serverHandshakeState) readFinished(out []byte) error {
	c := hs.c

	c.readRecord(recordTypeChangeCipherSpec)
	if err := c.in.error(); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	clientFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientFinished, msg)
	}

	verify := hs.finishedHash.clientSum(hs.masterSecret)
	if len(verify) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, clientFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: client's Finished message is incorrect")
	}

	hs.finishedHash.Write(clientFinished.marshal())
	copy(out, verify)
	return nil
}

func (hs *serverHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	c.writeRecord(recordTypeChangeCipherSpec, []byte{1})

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.serverSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	c.writeRecord(recordTypeHandshake, finished.marshal())

	c.cipherSuite = hs.suite.id
	copy(out, finished.verifyData)

	return nil
}

// setCipherSuite sets a cipherSuite with the given id as the serverHandshakeState
// suite if that cipher suite is acceptable to use.
// It returns a bool indicating if the suite was set.
func (hs *serverHandshakeState) setCipherSuite(id uint16, supportedCipherSuites []uint16, version uint16) bool {
	for _, supported := range supportedCipherSuites {
		if id == supported {
			var candidate *cipherSuite

			for _, s := range cipherSuites {
				if s.id == id {
					candidate = s
					break
				}
			}
			if candidate == nil {
				continue
			}
			// Don't select a ciphersuite which we can't
			// support for this client.
			if !hs.rsaSignOk {
				continue
			}
			if !hs.rsaDecryptOk {
				continue
			}
			hs.suite = candidate
			return true
		}
	}
	return false
}

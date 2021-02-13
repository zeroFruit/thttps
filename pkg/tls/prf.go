// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"hash"
)

// pHash implements the P_hash function, as defined in RFC 4346, section 5.
func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		todo := len(b)
		if j+todo > len(result) {
			todo = len(result) - j
		}
		copy(result[j:j+todo], b)
		j += todo

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

// prf12 implements the TLS 1.2 pseudo-random function, as defined in RFC 5246, section 5.
func prf12(hashFunc func() hash.Hash) func(result, secret, label, seed []byte) {
	return func(result, secret, label, seed []byte) {
		labelAndSeed := make([]byte, len(label)+len(seed))
		copy(labelAndSeed, label)
		copy(labelAndSeed[len(label):], seed)

		pHash(result, secret, labelAndSeed, hashFunc)
	}
}

const (
	masterSecretLength   = 48 // Length of a master secret in TLS 1.1.
	finishedVerifyLength = 12 // Length of verify_data in a Finished message.
)

var masterSecretLabel = []byte("master secret")
var keyExpansionLabel = []byte("key expansion")
var clientFinishedLabel = []byte("client finished")
var serverFinishedLabel = []byte("server finished")

func prfAndHashForVersion(version uint16) (func(result, secret, label, seed []byte), crypto.Hash) {
	switch version {
	case VersionTLS12:
		return prf12(sha256.New), crypto.SHA256
	default:
		panic("unknown version")
	}
}

func prfForVersion(version uint16) func(result, secret, label, seed []byte) {
	prf, _ := prfAndHashForVersion(version)
	return prf
}

// masterFromPreMasterSecret generates the master secret from the pre-master
// secret. See http://tools.ietf.org/html/rfc5246#section-8.1
func masterFromPreMasterSecret(version uint16, preMasterSecret, clientRandom, serverRandom []byte) []byte {
	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)

	masterSecret := make([]byte, masterSecretLength)
	prfForVersion(version)(masterSecret, preMasterSecret, masterSecretLabel, seed)
	return masterSecret
}

// keysFromMasterSecret generates the connection keys from the master
// secret, given the lengths of the MAC key, cipher key and IV, as defined in
// RFC 2246, section 6.3.
func keysFromMasterSecret(version uint16, masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	n := 2*macLen + 2*keyLen + 2*ivLen
	keyMaterial := make([]byte, n)
	prfForVersion(version)(keyMaterial, masterSecret, keyExpansionLabel, seed)
	clientMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	clientIV = keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]
	serverIV = keyMaterial[:ivLen]
	return
}

// lookupTLSHash looks up the corresponding crypto.Hash for a given
// TLS hash identifier.
func lookupTLSHash(hash uint8) (crypto.Hash, error) {
	switch hash {
	case hashSHA1:
		return crypto.SHA1, nil
	case hashSHA256:
		return crypto.SHA256, nil
	case hashSHA384:
		return crypto.SHA384, nil
	default:
		return 0, errors.New("tls: unsupported hash algorithm")
	}
}

func newFinishedHash(version uint16) finishedHash {
	var buffer []byte
	prf, hash := prfAndHashForVersion(version)
	if hash != 0 {
		return finishedHash{hash.New(), hash.New(), nil, nil, buffer, version, prf}
	}

	return finishedHash{sha1.New(), sha1.New(), md5.New(), md5.New(), buffer, version, prf}
}

// A finishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type finishedHash struct {
	client hash.Hash
	server hash.Hash

	// Prior to TLS 1.2, an additional MD5 hash is required.
	clientMD5 hash.Hash
	serverMD5 hash.Hash

	// In TLS 1.2, a full buffer is sadly required.
	buffer []byte

	version uint16
	prf     func(result, secret, label, seed []byte)
}

func (h *finishedHash) Write(msg []byte) (n int, err error) {
	h.client.Write(msg)
	h.server.Write(msg)

	if h.version < VersionTLS12 {
		h.clientMD5.Write(msg)
		h.serverMD5.Write(msg)
	}

	if h.buffer != nil {
		h.buffer = append(h.buffer, msg...)
	}

	return len(msg), nil
}

func (h finishedHash) Sum() []byte {
	if h.version >= VersionTLS12 {
		return h.client.Sum(nil)
	}

	out := make([]byte, 0, md5.Size+sha1.Size)
	out = h.clientMD5.Sum(out)
	return h.client.Sum(out)
}

// clientSum returns the contents of the verify_data member of a client's
// Finished message.
func (h finishedHash) clientSum(masterSecret []byte) []byte {
	out := make([]byte, finishedVerifyLength)
	h.prf(out, masterSecret, clientFinishedLabel, h.Sum())
	return out
}

// serverSum returns the contents of the verify_data member of a server's
// Finished message.
func (h finishedHash) serverSum(masterSecret []byte) []byte {
	out := make([]byte, finishedVerifyLength)
	h.prf(out, masterSecret, serverFinishedLabel, h.Sum())
	return out
}

// hashForClientCertificate returns a digest, hash function, and TLS 1.2 hash
// id suitable for signing by a TLS client certificate.
func (h finishedHash) hashForClientCertificate(signatureAndHash signatureAndHash, masterSecret []byte) ([]byte, crypto.Hash, error) {
	if h.version >= VersionTLS12 {
		hashAlg, err := lookupTLSHash(signatureAndHash.hash)
		if err != nil {
			return nil, 0, err
		}
		hash := hashAlg.New()
		hash.Write(h.buffer)
		return hash.Sum(nil), hashAlg, nil
	}

	return h.Sum(), crypto.MD5SHA1, nil
}

// discardHandshakeBuffer is called when there is no more need to
// buffer the entirety of the handshake messages.
func (h *finishedHash) discardHandshakeBuffer() {
	h.buffer = nil
}

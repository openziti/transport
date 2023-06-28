package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"math/big"
	"net"
	"testing"
	"time"
)

type testIdentity struct {
	serverCert *tls.Certificate
	clientCert *tls.Certificate
	capool     *x509.CertPool
}

var serverId testIdentity
var clientId testIdentity

const (
	CA_cert = iota
	Server_cert
	Client_cert
)

func init() {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(CA_cert),
		Subject: pkix.Name{
			CommonName:   "testCA",
			Organization: []string{"Openziti"},
			Country:      []string{"US"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute * 20),

		SignatureAlgorithm: x509.ECDSAWithSHA256,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},

		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, caKey.Public(), caKey)
	caCert, _ := x509.ParseCertificate(caCertBytes)

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(Server_cert),
		Subject: pkix.Name{
			CommonName:   "testServer",
			Organization: []string{"Openziti"},
			Country:      []string{"US"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute * 5),

		SignatureAlgorithm: x509.ECDSAWithSHA256,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,

		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1).To4()},
	}

	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	servCert, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, serverKey.Public(), caKey)
	if err != nil {
		panic(err)
	}

	cltTemplate := x509.Certificate{
		SerialNumber: big.NewInt(Client_cert),
		Subject: pkix.Name{
			CommonName:   "testClient",
			Organization: []string{"Openziti"},
			Country:      []string{"US"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute * 5),

		SignatureAlgorithm: x509.ECDSAWithSHA256,

		SubjectKeyId:          []byte{1, 2, 3, 4},
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientCert, err := x509.CreateCertificate(rand.Reader, &cltTemplate, &caTemplate, clientKey.Public(), caKey)
	if err != nil {
		panic(err)
	}

	serverId = testIdentity{
		serverCert: &tls.Certificate{
			Certificate: [][]byte{servCert},
			PrivateKey:  serverKey,
		},
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	clientId = testIdentity{
		capool: pool,
		clientCert: &tls.Certificate{
			Certificate: [][]byte{clientCert},
			PrivateKey:  clientKey,
		},
	}
}

func (t testIdentity) Cert() *tls.Certificate {
	return t.clientCert
}

func (t testIdentity) ServerCert() []*tls.Certificate {
	return []*tls.Certificate{t.serverCert}
}

func (t testIdentity) CA() *x509.CertPool {
	return t.capool
}

func (t testIdentity) CaPool() *identity.CaPool {
	//TODO implement me
	panic("implement me")
}

func (t testIdentity) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		ClientAuth:   tls.RequireAnyClientCert,
		Certificates: []tls.Certificate{*t.serverCert},
	}
}

func (t testIdentity) ClientTLSConfig() *tls.Config {
	return &tls.Config{
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return t.clientCert, nil
		},
		RootCAs: t.capool,
	}
}

func (t testIdentity) Reload() error {
	//TODO implement me
	panic("implement me")
}

func (t testIdentity) WatchFiles() error {
	//TODO implement me
	panic("implement me")
}

func (t testIdentity) StopWatchingFiles() {
	//TODO implement me
	panic("implement me")
}

func (t testIdentity) SetCert(pem string) error {
	//TODO implement me
	panic("implement me")
}

func (t testIdentity) SetServerCert(pem string) error {
	//TODO implement me
	panic("implement me")
}

func (t testIdentity) GetConfig() *identity.Config {
	//TODO implement me
	panic("implement me")
}

func makeGreeter(proto string) func(c transport.Conn) {
	return func(c transport.Conn) {
		msg := "Hello from " + proto
		_, _ = c.Write([]byte(msg))
		_ = c.Close()
	}
}

func checkClient(addr string, proto string, expected string, t *testing.T) error {
	clt := &identity.TokenId{
		Identity: clientId,
		Token:    "client",
		Data:     nil,
	}

	var c transport.Conn
	var err error
	if proto == "" {
		c, err = Dial(addr, "test-dialer", clt, time.Second)

	} else {
		c, err = Dial(addr, "test-dialer", clt, time.Second, proto)
	}
	if err != nil {
		return err
	}

	tlsConn := c.(*Connection)
	fmt.Println("proto = ", tlsConn.Protocol())
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil {
		return err
	} else {
		recv := string(buf[:n])
		fmt.Println(recv)
		if recv != "Hello from "+expected {
			t.Error("wrong handler")
		}
	}
	return nil
}

func TestListen(t *testing.T) {

	ident := &identity.TokenId{
		Identity: serverId,
		Token:    "test",
		Data:     nil,
	}

	testAddress := "localhost:14444"

	if _, ok := sharedListeners.Load(testAddress); ok {
		t.Error("should be empty")
	}

	fooListener, err := Listen(testAddress, "fooListener", ident, makeGreeter("foo"), "foo")

	count := 0
	sharedListeners.Range(func(key, value any) bool {
		count++
		return true
	})
	if count != 1 {
		t.Error("should have single shared listener")
	}

	el, ok := sharedListeners.Load(testAddress)
	if !ok {
		t.Error("should have shared listener")
	}

	barListener, err := Listen(testAddress, "fooListener", ident, makeGreeter("bar"), "bar", "")

	el, ok = sharedListeners.Load(testAddress)
	if !ok {
		t.Error("should have shared listener")
	}

	sl := el.(*sharedListener)
	if len(sl.acceptors) != 3 {
		t.Error("should have a three handled protocols")
	}

	if sl.acceptors[""] != sl.acceptors["bar"] {
		t.Error("should be handled by the same acceptor")
	}

	if err != nil {
		t.Error(err)
	}

	if err = checkClient(testAddress, "foo", "foo", t); err != nil {
		t.Error(err)
	}
	if err = checkClient(testAddress, "bar", "bar", t); err != nil {
		t.Error(err)
	}

	err = checkClient(testAddress, "baz", "baz", t)
	if err == nil {
		t.Error("this should've failed")
	}

	err = checkClient(testAddress, "", "bar", t)
	if err != nil {
		t.Error(err)
	}

	_ = fooListener.Close()

	err = checkClient(testAddress, "foo", "foo", t)
	if err == nil {
		t.Error("this should've failed")
	}

	if len(sl.acceptors) != 2 {
		t.Errorf("2 protocols should be remaining, found %d acceptors", len(sl.acceptors))
	}

	_ = barListener.Close()

	if _, ok = sharedListeners.Load(testAddress); ok {
		t.Error("failed to shutdown shared listener")
	}
}

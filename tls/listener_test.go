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
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

var _ identity.Identity = (*testIdentity)(nil)

type testIdentity struct {
	serverCert *tls.Certificate
	clientCert *tls.Certificate
	capool     *x509.CertPool
}

func (t testIdentity) GetX509ActiveClientCertChain() []*x509.Certificate {
	//TODO implement me
	panic("implement me")
}

func (t testIdentity) GetX509ActiveServerCertChains() [][]*x509.Certificate {
	//TODO implement me
	panic("implement me")
}

func (t testIdentity) GetX509IdentityServerCertChain() []*x509.Certificate {
	//TODO implement me
	panic("implement me")
}

func (t testIdentity) GetX509IdentityAltCertCertChains() [][]*x509.Certificate {
	//TODO implement me
	panic("implement me")
}

func (t testIdentity) GetCaPool() *identity.CaPool {
	//TODO implement me
	panic("implement me")
}

func (t testIdentity) CheckServerCertSansForConflicts() []identity.SanHostConflictError {
	//TODO implement me
	panic("implement me")
}

func (t testIdentity) ValidFor(hostnameOrIp string) error {
	//TODO implement me
	panic("implement me")
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
	caCertBytes, _ := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, caKey.Public(), caKey)
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

func (t testIdentity) SetCert(_ string) error {
	//TODO implement me
	panic("implement me")
}

func (t testIdentity) SetServerCert(_ string) error {
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

	transport.AddAddressParser(AddressParser{})
	tlsAddr, err := transport.ParseAddress("tls:" + addr)
	require.NoError(t, err)

	var c transport.Conn
	if proto == "" {
		c, err = Dial(*(tlsAddr.(*address)), "test-dialer", clt, time.Second, nil)
	} else {
		c, err = Dial(*(tlsAddr.(*address)), "test-dialer", clt, time.Second, nil, proto)
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
	req := require.New(t)

	ident := &identity.TokenId{
		Identity: serverId,
		Token:    "test",
		Data:     nil,
	}

	testAddress := "localhost:14444"

	if listeners, ok := sharedListeners.Load(testAddress); ok {
		req.Empty(listeners, "should be empty")
	}

	fooListener, err := Listen(testAddress, "fooListener", ident, makeGreeter("foo"), "foo")
	req.NoError(err)

	count := 0
	sharedListeners.Range(func(key, value any) bool {
		count++
		return true
	})

	req.Equal(1, count, "should have single shared listener")

	el, ok := sharedListeners.Load(testAddress)
	req.True(ok, "should have shared listener")
	sl := el.(*sharedListener)
	req.Equal(1, len(sl.handlers))

	barListener, err := Listen(testAddress, "fooListener", ident, makeGreeter("bar"), "bar", "")
	req.NoError(err)

	el, ok = sharedListeners.Load(testAddress)
	req.True(ok, "should have shared listener")

	sl = el.(*sharedListener)
	req.Equal(3, len(sl.handlers), "should have a three handled protocols")

	req.Same(sl.handlers[""], sl.handlers["bar"], "should be handled by the same protocolHandler")

	req.NoError(checkClient(testAddress, "foo", "foo", t))
	req.NoError(checkClient(testAddress, "bar", "bar", t))
	req.Error(checkClient(testAddress, "baz", "baz", t), "this should've failed")
	req.NoError(checkClient(testAddress, "", "bar", t))

	req.NoError(fooListener.Close())

	req.Error(checkClient(testAddress, "foo", "foo", t), "should fail after handler is closed")
	req.Equal(2, len(sl.handlers), "2 protocols should be remaining")
	req.NoError(barListener.Close())

	if _, ok = sharedListeners.Load(testAddress); ok {
		t.Error("failed to shutdown shared listener")
	}

	req.Error(checkClient(testAddress, "", "bar", t), "listen socket should be closed")
}

func TestListenTLS(t *testing.T) {
	req := require.New(t)

	ident := &identity.TokenId{
		Identity: serverId,
		Token:    "test",
		Data:     nil,
	}

	testAddress := "localhost:14444"

	if _, ok := sharedListeners.Load(testAddress); ok {
		t.Error("should be empty")
	}

	config := ident.ServerTLSConfig().Clone()
	config.NextProtos = []string{"h2", "http/1.1"}
	config.ClientAuth = tls.RequestClientCert

	httpListener, err := ListenTLS(testAddress, "web", config)
	req.NoError(err)

	fooListener, err := Listen(testAddress, "fooListener", ident, makeGreeter("foo"), "foo")
	req.NoError(err)

	httpServer := &http.Server{
		Addr:      testAddress,
		TLSConfig: config,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.TLS.PeerCertificates) > 0 {
				w.Header().Add("client-subject", r.TLS.PeerCertificates[0].Subject.CommonName)
				w.WriteHeader(200)
			} else {
				w.WriteHeader(401)
				_, _ = w.Write([]byte("I don't know you"))
			}
		}),
	}

	go func() {
		err := httpServer.Serve(httpListener)
		if err != nil {
			fmt.Println("server is done: ", err.Error())
		}
	}()

	cltTLS := clientId.ClientTLSConfig().Clone()
	clt := http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: cltTLS,
		},
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       0,
	}

	resp, err := clt.Get("https://" + testAddress)
	req.NoError(err)
	req.Equal(200, resp.StatusCode)
	req.Equal(2, resp.ProtoMajor)
	req.Equal("testClient", resp.Header["Client-Subject"][0])

	req.NoError(checkClient(testAddress, "foo", "foo", t), "should find handler")
	req.Error(checkClient(testAddress, "bar", "bar", t), "should have no handler")

	req.NoError(httpListener.Close())
	req.NoError(fooListener.Close())
}

func TestListenSingleProto(t *testing.T) {
	req := require.New(t)

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
	req.NoError(err)

	req.NoError(checkClient(testAddress, "foo", "foo", t), "should find handler")
	req.NoError(checkClient(testAddress, "", "foo", t), "should find handler")
	req.Error(checkClient(testAddress, "bar", "bar", t), "should have no handler")

	req.NoError(fooListener.Close())
}

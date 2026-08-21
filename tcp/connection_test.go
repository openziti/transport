package tcp

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/openziti/transport/v2"
	"github.com/stretchr/testify/require"
)

// TestConnectionCloseWrite covers the half-close discovery path callers actually use: a type
// assertion for CloseWrite on the transport.Conn, on both the dialed and the accepted side.
func TestConnectionCloseWrite(t *testing.T) {
	req := require.New(t)

	accepted := make(chan transport.Conn, 1)
	closer, err := Listen("127.0.0.1:0", "test-listener", func(c transport.Conn) {
		accepted <- c
	})
	req.NoError(err)
	defer func() { _ = closer.Close() }()

	listener, ok := closer.(net.Listener)
	req.True(ok, "Listen should return the underlying net.Listener")

	client, err := Dial(listener.Addr().String(), "test-dialer", 2*time.Second)
	req.NoError(err)
	defer func() { _ = client.Close() }()

	var server transport.Conn
	select {
	case server = <-accepted:
	case <-time.After(2 * time.Second):
		req.FailNow("timed out waiting for the connection to be accepted")
	}
	defer func() { _ = server.Close() }()

	clientHalfCloser, ok := client.(interface{ CloseWrite() error })
	req.True(ok, "dialed connection should support half-close")
	_, ok = server.(interface{ CloseWrite() error })
	req.True(ok, "accepted connection should support half-close")

	_, err = client.Write([]byte("ping"))
	req.NoError(err)
	req.NoError(clientHalfCloser.CloseWrite())

	req.NoError(server.SetReadDeadline(time.Now().Add(2 * time.Second)))
	buf := make([]byte, 16)
	n, err := server.Read(buf)
	req.NoError(err)
	req.Equal("ping", string(buf[:n]))

	// half-close, not a full close: the peer reads EOF, but the reverse direction still carries data
	_, err = server.Read(buf)
	req.ErrorIs(err, io.EOF)

	_, err = server.Write([]byte("pong"))
	req.NoError(err)

	req.NoError(client.SetReadDeadline(time.Now().Add(2 * time.Second)))
	n, err = client.Read(buf)
	req.NoError(err)
	req.Equal("pong", string(buf[:n]))
}

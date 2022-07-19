/*
	Copyright NetFoundry Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package ws

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/openziti/transport/v2"
	"github.com/sirupsen/logrus"
	// _ "unsafe"	// Using go:linkname requires us to import unsafe
)

var (
	errClosing = errors.New(`Closing`)

	browZerRuntimeSdkSuites = []uint16{

		//vv JS-based TLS1.2 suites (here until we fully retire Forge on browser-side)
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		//^^

		//vv WASM-based TLS1.3 suites
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_128_GCM_SHA256,
		//^^
	}
)

// safeBuffer adds thread-safety to *bytes.Buffer
type safeBuffer struct {
	buf *bytes.Buffer
	log *logrus.Entry
	sync.Mutex
}

// Read reads the next len(p) bytes from the buffer or until the buffer is drained.
func (s *safeBuffer) Read(p []byte) (int, error) {
	s.Lock()
	defer s.Unlock()
	return s.buf.Read(p)
}

// Write appends the contents of p to the buffer.
func (s *safeBuffer) Write(p []byte) (int, error) {
	s.Lock()
	defer s.Unlock()
	return s.buf.Write(p)
}

// Len returns the number of bytes of the unread portion of the buffer.
func (s *safeBuffer) Len() int {
	s.Lock()
	defer s.Unlock()
	return s.buf.Len()
}

// Reset resets the buffer to be empty.
func (s *safeBuffer) Reset() {
	s.Lock()
	s.buf.Reset()
	s.Unlock()
}

// Connection wraps gorilla websocket to provide io.ReadWriteCloser
type Connection struct {
	detail                   *transport.ConnectionDetail
	cfg                      *Config
	ws                       *websocket.Conn
	tlsConn                  *tls.Conn
	tlsConnHandshakeComplete bool
	log                      *logrus.Entry
	rxbuf                    *safeBuffer
	txbuf                    *safeBuffer
	tlsrxbuf                 *safeBuffer
	tlstxbuf                 *safeBuffer
	done                     chan struct{}
	wmutex                   sync.Mutex
	rmutex                   sync.Mutex
	tlswmutex                sync.Mutex
	tlsrmutex                sync.Mutex
	readCallDepth            int32
	writeCallDepth           int32
	connid                   int64
}

// Read implements io.Reader by wrapping websocket messages in a buffer.
func (c *Connection) Read(p []byte) (n int, err error) {
	currentDepth := atomic.AddInt32(&c.readCallDepth, 1)
	c.log.Tracef("Read() start currentDepth[%d]", currentDepth)

	if c.rxbuf.Len() == 0 {
		var r io.Reader
		c.rxbuf.Reset()
		if c.tlsConnHandshakeComplete {
			if currentDepth == 1 {
				c.tlsrmutex.Lock()
				defer c.tlsrmutex.Unlock()
			} else if currentDepth == 2 {
				c.rmutex.Lock()
				defer c.rmutex.Unlock()
			}
		} else {
			c.rmutex.Lock()
			defer c.rmutex.Unlock()
		}
		select {
		case <-c.done:
			err = errClosing
		default:
			if c.tlsConnHandshakeComplete && currentDepth == 1 {
				n, err = c.tlsConn.Read(p)
				atomic.SwapInt32(&c.readCallDepth, c.readCallDepth-1)
				c.log.Tracef("Read() end currentDepth[%d]", currentDepth)
				return n, err
			} else {
				_, r, err = c.ws.NextReader()
			}
		}
		if err != nil {
			c.log.Errorf("Read() connid[%d] ************** err[%v]", c.connid, err)
			return n, err
		}
		_, err = io.Copy(c.rxbuf, r)
		if err != nil {
			c.log.Errorf("Read() connid[%d] ************** err[%v]", c.connid, err)
			return n, err
		}
		c.log.Tracef("Read() connid[%d] after io.Copy currentDepth[%d] c.rxbuf.Len[%d]", c.connid, currentDepth, c.rxbuf.Len())
	}

	atomic.SwapInt32(&c.readCallDepth, c.readCallDepth-1)

	return c.rxbuf.Read(p)
}

// Write implements io.Writer and sends binary messages only.
func (c *Connection) Write(p []byte) (n int, err error) {
	return c.write(websocket.BinaryMessage, p)
}

// write wraps the websocket writer.
func (c *Connection) write(messageType int, p []byte) (n int, err error) {
	var txbufLen int
	currentDepth := atomic.AddInt32(&c.writeCallDepth, 1)
	c.log.Tracef("Write() start currentDepth[%d] len[%d]", c.writeCallDepth, len(p))

	if c.tlsConnHandshakeComplete {
		if currentDepth == 1 {
			c.tlswmutex.Lock()
			defer c.tlswmutex.Unlock()
		} else if currentDepth == 2 {
			c.wmutex.Lock()
			defer c.wmutex.Unlock()
		}
	} else {
		c.wmutex.Lock()
		defer c.wmutex.Unlock()
	}

	select {
	case <-c.done:
		err = errClosing
	default:
		var txbufLen int

		if !c.tlsConnHandshakeComplete {
			_, _ = c.tlstxbuf.Write(p)
			txbufLen = c.tlstxbuf.Len()
			c.log.Tracef("Write() doing TLS handshake (buffering); currentDepth[%d] txbufLen[%d] data[%o]", c.writeCallDepth, txbufLen, p)
		} else if currentDepth == 1 { // if at TLS level (1st level)
			_, _ = c.tlstxbuf.Write(p)
			txbufLen = c.tlstxbuf.Len()
			c.log.Tracef("Write() doing TLS write; currentDepth[%d] txbufLen[%d] data[%o]", c.writeCallDepth, txbufLen, p)
		} else { // if at websocket level (2nd level)
			_, _ = c.txbuf.Write(p)
			txbufLen = c.txbuf.Len()
			c.log.Tracef("Write() doing raw write; currentDepth[%d] txbufLen[%d] data[%o]", c.writeCallDepth, txbufLen, p)
		}

		err = c.ws.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout))
		if err == nil {
			if !c.tlsConnHandshakeComplete {
				m := make([]byte, txbufLen)
				_, _ = c.tlstxbuf.Read(m)
				c.log.Tracef("Write() doing TLS handshake (to websocket); currentDepth[%d] txbufLen[%d] data[%o]", c.writeCallDepth, txbufLen, m)
				err = c.ws.WriteMessage(messageType, m)
			} else if currentDepth == 1 {
				m := make([]byte, txbufLen)
				_, _ = c.tlstxbuf.Read(m)
				c.log.Tracef("Write() doing TLS write (to conn); currentDepth[%d] txbufLen[%d] data[%o]", c.writeCallDepth, txbufLen, m)
				n, err = c.tlsConn.Write(m)
				atomic.SwapInt32(&c.writeCallDepth, c.writeCallDepth-1)
				c.log.Tracef("write() end TLS write currentDepth[%d]", c.writeCallDepth)
				return n, err
			} else {
				m := make([]byte, txbufLen)
				_, _ = c.txbuf.Read(m)
				c.log.Tracef("Write() doing raw write (to websocket); currentDepth[%d] len[%d]", c.writeCallDepth, len(m))
				err = c.ws.WriteMessage(messageType, m)
			}
		}
	}
	if err == nil {
		n = txbufLen
	}
	atomic.SwapInt32(&c.writeCallDepth, c.writeCallDepth-1)
	c.log.Tracef("Write() end currentDepth[%d]", c.writeCallDepth)

	return n, err
}

// Close implements io.Closer and closes the underlying connection.
func (c *Connection) Close() error {
	c.rmutex.Lock()
	c.wmutex.Lock()
	defer func() {
		c.rmutex.Unlock()
		c.wmutex.Unlock()
	}()
	select {
	case <-c.done:
		return errClosing
	default:
		close(c.done)
	}
	return c.ws.Close()
}

// pinger sends ping messages on an interval for client keep-alive.
func (c *Connection) pinger() {
	ticker := time.NewTicker(c.cfg.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.log.Trace("sending websocket Ping")
			if _, err := c.write(websocket.PingMessage, []byte{}); err != nil {
				_ = c.Close()
			}
		}
	}
}

// tlsHandshake wraps the websocket in a TLS server.
func (c *Connection) tlsHandshake() error {

	cfg := c.cfg.Identity.ServerTLSConfig()
	cfg.ClientAuth = tls.RequireAndVerifyClientCert

	// This is technically not correct but will help get work moving forward.
	// Instead of using ClientCAs we should rely on VerifyPeerCertificate
	// or VerifyConnection similar to how the controller does it
	cfg.ClientCAs = cfg.RootCAs
	cfg.CipherSuites = append(cfg.CipherSuites, browZerRuntimeSdkSuites...)

	c.tlsConn = tls.Server(c, cfg)
	if err := c.tlsConn.Handshake(); err != nil {
		if err != nil {
			c.log.Error(err)
			_ = c.Close()
			return err
		}
	}

	c.tlsConnHandshakeComplete = true

	c.log.Info("TLS Handshake completed successfully")

	return nil
}

// newSafeBuffer instantiates a new safeBuffer
func newSafeBuffer(log *logrus.Entry) *safeBuffer {
	return &safeBuffer{
		buf: bytes.NewBuffer(nil),
		log: log,
	}
}

func (c *Connection) Detail() *transport.ConnectionDetail {
	return c.detail
}

func (c *Connection) PeerCertificates() []*x509.Certificate {
	if c.tlsConnHandshakeComplete {
		return c.tlsConn.ConnectionState().PeerCertificates
	} else {
		return nil
	}
}

func (c *Connection) LocalAddr() net.Addr {
	return c.ws.UnderlyingConn().LocalAddr()
}
func (c *Connection) RemoteAddr() net.Addr {
	return c.ws.UnderlyingConn().RemoteAddr()
}
func (c *Connection) SetDeadline(t time.Time) error {
	return c.ws.UnderlyingConn().SetDeadline(t)
}
func (c *Connection) SetReadDeadline(t time.Time) error {
	return c.ws.UnderlyingConn().SetReadDeadline(t)
}
func (c *Connection) SetWriteDeadline(t time.Time) error {
	return c.ws.UnderlyingConn().SetWriteDeadline(t)
}

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

package wss

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/gorilla/websocket"
	"github.com/openziti/transport/v2"
	"github.com/openziti/transport/v2/ws"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"sync"
	"time"
)

var (
	errClosing = errors.New(`Closing`)
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
	detail *transport.ConnectionDetail
	cfg    *ws.Config
	ws     *websocket.Conn
	log    *logrus.Entry
	rxbuf  *safeBuffer
	txbuf  *safeBuffer
	done   chan struct{}
	wmutex sync.Mutex
	rmutex sync.Mutex
}

func (c *Connection) LocalAddr() net.Addr {
	return c.ws.LocalAddr()
}

func (c *Connection) RemoteAddr() net.Addr {
	return c.ws.RemoteAddr()
}

func (c *Connection) SetDeadline(t time.Time) error {
	return c.ws.UnderlyingConn().SetDeadline(t)
}

func (c *Connection) SetReadDeadline(t time.Time) error {
	return c.ws.SetReadDeadline(t)
}

func (c *Connection) SetWriteDeadline(t time.Time) error {
	return c.ws.SetWriteDeadline(t)
}

// Read implements io.Reader by wrapping websocket messages in a buffer.
func (c *Connection) Read(p []byte) (n int, err error) {
	if c.rxbuf.Len() == 0 {
		var r io.Reader
		c.rxbuf.Reset()
		c.rmutex.Lock()
		defer c.rmutex.Unlock()
		select {
		case <-c.done:
			err = errClosing
		default:
			_, r, err = c.ws.NextReader()
		}
		if err != nil {
			return n, err
		}
		_, err = io.Copy(c.rxbuf, r)
		if err != nil {
			return n, err
		}
	}

	return c.rxbuf.Read(p)
}

// Write implements io.Writer and sends binary messages only.
func (c *Connection) Write(p []byte) (n int, err error) {
	return c.write(websocket.BinaryMessage, p)
}

// write wraps the websocket writer.
func (c *Connection) write(messageType int, p []byte) (n int, err error) {
	var txbufLen int
	c.wmutex.Lock()
	defer c.wmutex.Unlock()
	select {
	case <-c.done:
		err = errClosing
	default:
		_, _ = c.txbuf.Write(p)
		txbufLen = c.txbuf.Len()
		if txbufLen > 20 { // TEMP HACK:  (until I refactor the JS-SDK to accept the message section and data section in separate salvos)
			err = c.ws.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout))
			if err == nil {
				m := make([]byte, txbufLen)
				_, _ = c.txbuf.Read(m)
				err = c.ws.WriteMessage(messageType, m)
			}
		}
	}
	if err == nil {
		n = txbufLen
	}
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
	var tlsConn = c.ws.UnderlyingConn().(*tls.Conn)
	return tlsConn.ConnectionState().PeerCertificates
}

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

package dtls

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync/atomic"
	"time"

	"log/slog"

	"github.com/openziti/foundation/v2/logging"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"github.com/openziti/transport/v2/shaper"
	"github.com/pion/dtls/v3"
)

const DefaultHandshakeTimeout = 30 * time.Second

func Listen(addr *address, name string, i *identity.TokenId, tcfg transport.Configuration, acceptF func(transport.Conn)) (io.Closer, error) {
	if addr.err != nil {
		return nil, addr.err
	}

	timeout, err := tcfg.GetHandshakeTimeout()
	if err != nil {
		return nil, err
	}

	if timeout == 0 {
		timeout = DefaultHandshakeTimeout
	}

	log := logging.For("transport.dtls").With("endpoint", name+"/"+addr.String())

	var certs []tls.Certificate

	for _, ptrCert := range i.ServerCert() {
		certs = append(certs, *ptrCert)
	}

	listener, err := dtls.ListenWithOptions("udp", &addr.UDPAddr,
		dtls.WithCertificates(certs...),
		dtls.WithClientAuth(dtls.RequireAnyClientCert),
		dtls.WithRootCAs(i.CA()),
	)
	if err != nil {
		return nil, err
	}

	wf := func(w io.Writer) io.Writer {
		return w
	}

	bps, found, err := tcfg.GetInt64Value("dtls", "maxBytesPerSecond")
	if err != nil {
		return nil, err
	}
	if found {
		log.Info("limiting DTLS writes", "bytesPerSecond", bps)
		wf = func(w io.Writer) io.Writer {
			return shaper.LimitWriter(w, time.Second, bps)
		}
	}

	result := &acceptor{
		name:     name,
		listener: listener,
		acceptF:  acceptF,
		timeout:  timeout,
		wf:       wf,
	}

	go result.acceptLoop(log)

	return result, nil
}

type acceptor struct {
	name     string
	listener net.Listener
	acceptF  func(transport.Conn)
	closed   atomic.Bool
	timeout  time.Duration
	wf       func(io.Writer) io.Writer
}

func (self *acceptor) Close() error {
	if self.closed.CompareAndSwap(false, true) {
		return self.listener.Close()
	}
	return nil
}

func (self *acceptor) acceptLoop(log *slog.Logger) {
	defer log.Info("exited")

	for !self.closed.Load() {
		socket, err := self.listener.Accept()
		if err != nil {
			if self.closed.Load() {
				log.Info("listener closed, exiting", "error", err)
				return
			}
			log.Error("accept failed. failure not recoverable. exiting listen loop", "error", err)
			return
		}

		conn := socket.(*dtls.Conn)
		ctx := context.Background()
		cancelF := func() {}
		if self.timeout > 0 {
			ctx, cancelF = context.WithTimeout(ctx, self.timeout)
		}
		err = conn.HandshakeContext(ctx)
		cancelF()

		if err != nil {
			log.Error("dtls handshake error", "error", err)
			if err = conn.Close(); err != nil {
				log.Error("error closing connection", "error", err)
			}
			continue
		}

		certs, err := getPeerCerts(conn)
		if err != nil {
			log.Error("unable to parse peer certificates", "error", err)
			if err = conn.Close(); err != nil {
				log.Error("error closing connection", "error", err)
			}
			continue
		}

		connection := &Connection{
			detail: &transport.ConnectionDetail{
				Address: Type + ":" + socket.RemoteAddr().String(),
				InBound: true,
				Name:    self.name,
			},
			certs: certs,
			Conn:  conn,
			w:     self.wf(conn),
		}
		self.acceptF(connection)
	}
}

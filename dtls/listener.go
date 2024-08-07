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
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"github.com/pion/dtls/v3"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"sync/atomic"
	"time"
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

	log := pfxlog.ContextLogger(name + "/" + addr.String()).Entry

	var certs []tls.Certificate

	for _, ptrCert := range i.ServerCert() {
		certs = append(certs, *ptrCert)
	}

	cfg := &dtls.Config{
		Certificates: certs,
		//ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ClientAuth: dtls.RequireAnyClientCert,
		RootCAs:    i.CA(),
		//CipherSuites:         tlz.GetCipherSuites(),
		// Create timeout context for accepted connection.
	}

	listener, err := dtls.Listen("udp", &addr.UDPAddr, cfg)
	if err != nil {
		return nil, err
	}

	result := &acceptor{
		name:     name,
		listener: listener,
		acceptF:  acceptF,
		timeout:  timeout,
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
}

func (self *acceptor) Close() error {
	if self.closed.CompareAndSwap(false, true) {
		return self.listener.Close()
	}
	return nil
}

func (self *acceptor) acceptLoop(log *logrus.Entry) {
	defer log.Info("exited")

	for !self.closed.Load() {
		socket, err := self.listener.Accept()
		if err != nil {
			if self.closed.Load() {
				log.WithError(err).Info("listener closed, exiting")
				return
			}
			log.WithError(err).Error("accept failed. Failure not recoverable. Exiting listen loop")
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
			log.WithError(err).Error("dtls handshake error")
			if err = conn.Close(); err != nil {
				log.WithError(err).Error("error closing connection")
			}
			continue
		}

		certs, err := getPeerCerts(conn)
		if err != nil {
			log.WithError(err).Error("unable to parse peer certificates")
			if err = conn.Close(); err != nil {
				log.WithError(err).Error("error closing connection")
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
		}
		self.acceptF(connection)
	}
}

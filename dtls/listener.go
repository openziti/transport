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
	"github.com/openziti/foundation/v2/concurrenz"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"github.com/pion/dtls/v2"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"time"
)

func Listen(addr *address, name string, i *identity.TokenId, acceptF func(transport.Conn)) (io.Closer, error) {
	if addr.err != nil {
		return nil, addr.err
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
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(context.Background(), 30*time.Second)
		},
	}

	listener, err := dtls.Listen("udp", &addr.UDPAddr, cfg)
	if err != nil {
		return nil, err
	}

	result := &acceptor{
		name:     name,
		listener: listener,
		acceptF:  acceptF,
	}

	go result.acceptLoop(log)

	return result, nil
}

type acceptor struct {
	name     string
	listener net.Listener
	acceptF  func(transport.Conn)
	closed   concurrenz.AtomicBoolean
}

func (self *acceptor) Close() error {
	if self.closed.CompareAndSwap(false, true) {
		return self.listener.Close()
	}
	return nil
}

func (self *acceptor) acceptLoop(log *logrus.Entry) {
	defer log.Info("exited")

	for !self.closed.Get() {
		socket, err := self.listener.Accept()
		if err != nil {
			if self.closed.Get() {
				log.WithError(err).Info("listener closed, exiting")
				return
			}
			if netErr, ok := err.(net.Error); ok && !netErr.Temporary() {
				log.WithError(err).Error("accept failed. Failure not recoverable. Exiting listen loop")
				return
			}
			log.WithError(err).Error("accept failed")
			continue
		}

		conn := socket.(*dtls.Conn)
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
			Conn:  socket.(*dtls.Conn),
		}
		self.acceptF(connection)
	}
}

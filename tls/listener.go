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

package tls

import (
	"crypto/tls"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/foundation/v2/concurrenz"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"github.com/sirupsen/logrus"
	"io"
	"net"
)

func Listen(bindAddress, name string, i *identity.TokenId, acceptF func(transport.Conn)) (io.Closer, error) {
	log := pfxlog.ContextLogger(name + "/" + Type + ":" + bindAddress).Entry

	listener, err := tls.Listen("tcp", bindAddress, i.ServerTLSConfig())
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
	acceptF  func(conn transport.Conn)
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
				log.WithField("err", err).Info("listener closed, exiting")
				return
			}
			if netErr, ok := err.(net.Error); ok && !netErr.Temporary() {
				log.WithField("err", err).Error("accept failed. Failure not recoverable. Exiting listen loop")
				return
			}
			log.WithField("err", err).Error("accept failed")
		} else {
			connection := &Connection{
				detail: &transport.ConnectionDetail{
					Address: Type + ":" + socket.RemoteAddr().String(),
					InBound: true,
					Name:    self.name,
				},
				Conn: socket.(*tls.Conn),
			}
			self.acceptF(connection)
		}
	}
}

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

package udp

import (
	"bufio"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"github.com/openziti/transport/v2/udpconn"
	"github.com/sirupsen/logrus"
	"io"
	"math"
	"net"
)

func Listen(bindAddress *net.UDPAddr, name string, i *identity.TokenId, acceptF func(transport.Conn)) (io.Closer, error) {
	log := pfxlog.ContextLogger(name + "/" + Type + ":" + bindAddress.String())

	listener, err := udpconn.Listen("udp", bindAddress)
	if err != nil {
		return nil, err
	}

	go acceptLoop(log.Entry, name, listener, acceptF)

	return listener, nil
}

func acceptLoop(log *logrus.Entry, name string, listener net.Listener, acceptF func(transport.Conn)) {
	defer log.Error("exited")

	for {
		socket, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && !netErr.Temporary() {
				log.WithField("err", err).Error("accept failed. Failure not recoverable. Exiting listen loop")
				return
			}
			log.WithField("err", err).Error("accept failed")
		} else {
			log.Info("new udp connection accepted")
			connection := &Connection{
				detail: &transport.ConnectionDetail{
					Address: Type + ":" + socket.RemoteAddr().String(),
					InBound: true,
					Name:    name,
				},
				Conn:   socket,
				reader: bufio.NewReaderSize(socket, math.MaxUint16),
			}
			acceptF(connection)
		}
	}
}

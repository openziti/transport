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

package tcp

import (
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/transport/v2"
	"github.com/sirupsen/logrus"
	"io"
	"net"
)

func Listen(bindAddress, name string, acceptF func(transport.Conn)) (io.Closer, error) {
	log := pfxlog.ContextLogger(name + "/" + Type + ":" + bindAddress)

	listener, err := net.Listen("tcp", bindAddress)
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
			log.WithField("err", err).Error("accept failed. failure not recoverable. exiting listen loop")
			return
		} else {
			connection := &Connection{
				detail: &transport.ConnectionDetail{
					Address: Type + ":" + socket.RemoteAddr().String(),
					InBound: true,
					Name:    name,
				},
				Conn: socket,
			}
			acceptF(connection)

			log.WithField("addr", socket.RemoteAddr().String()).Info("accepted connection")
		}
	}
}

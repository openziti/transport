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
	"crypto/x509"
	"fmt"
	"net"

	"github.com/openziti/transport/v2"
)

var _ interface{ CloseWrite() error } = (*Connection)(nil) // enforce that Connection exposes the socket's half-close

// Connection is a TCP transport connection. It embeds *net.TCPConn rather than net.Conn so
// that the TCP-specific parts of the socket, notably CloseWrite for half-close, stay reachable
// through it. Datagram transports have no equivalent, so they keep the net.Conn interface.
type Connection struct {
	detail *transport.ConnectionDetail
	*net.TCPConn
}

func (self *Connection) Detail() *transport.ConnectionDetail {
	return self.detail
}

func (self *Connection) PeerCertificates() []*x509.Certificate {
	return nil
}

// asTCPConn narrows a socket to its TCP type. Every socket this package creates comes from
// dialing or listening on "tcp", so the assertion holds; it returns an error rather than
// panicking so a future caller wiring in another socket type fails visibly.
func asTCPConn(socket net.Conn) (*net.TCPConn, error) {
	tcpConn, ok := socket.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("expected *net.TCPConn, got %T", socket)
	}
	return tcpConn, nil
}

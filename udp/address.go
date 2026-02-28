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
	"fmt"
	"io"
	"net"
	"time"

	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
)

var _ transport.Address = &address{} // enforce that address implements transport.Address

const Type = "udp"

type address struct {
	hostname string
	port     uint16
}

func (a address) Dial(name string, i *identity.TokenId, timeout time.Duration, _ transport.Configuration) (transport.Conn, error) {
	addr, err := a.bindableAddress()
	if err != nil {
		return nil, err
	}
	return Dial(addr, name, i, timeout)
}

func (a address) DialWithLocalBinding(name string, localBinding string, _ *identity.TokenId, timeout time.Duration, _ transport.Configuration) (transport.Conn, error) {
	addr, err := a.bindableAddress()
	if err != nil {
		return nil, err
	}
	return DialWithLocalBinding(addr, name, localBinding, timeout)
}

func (a address) Listen(name string, i *identity.TokenId, acceptF func(transport.Conn), _ transport.Configuration) (io.Closer, error) {
	addr, err := a.bindableAddress()
	if err != nil {
		return nil, err
	}
	return Listen(addr, name, i, acceptF)
}

func (a address) MustListen(name string, i *identity.TokenId, acceptF func(transport.Conn), tcfg transport.Configuration) io.Closer {
	closer, err := a.Listen(name, i, acceptF, tcfg)
	if err != nil {
		panic(err)
	}
	return closer
}

func (a address) String() string {
	return fmt.Sprintf("%s:%s", Type, transport.HostPortString(a.hostname, a.port))
}

func (a address) bindableAddress() (*net.UDPAddr, error) {
	return net.ResolveUDPAddr("udp", transport.HostPortString(a.hostname, a.port))
}

func (a address) Type() string {
	return Type
}

func (a address) Hostname() string {
	return a.hostname
}

func (a address) Port() uint16 {
	return a.port
}

type AddressParser struct{}

func (ap AddressParser) Parse(s string) (transport.Address, error) {
	host, port, err := transport.ParseAddressHostPort(s, Type)
	if err != nil {
		return nil, err
	}
	return &address{hostname: host, port: port}, nil
}

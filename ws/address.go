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
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
)

var _ transport.Address = &address{} // enforce that address implements transport.Address

const Type = "ws"
const unsupportedErr = "transport.ws not supported. use transport.wss"

type address struct {
	hostname string
	port     uint16
}

func (address) Dial(name string, i *identity.TokenId, timeout time.Duration, tcfg transport.Configuration) (transport.Conn, error) {
	return nil, errors.New(unsupportedErr)
}

func (address) DialWithLocalBinding(name string, binding string, i *identity.TokenId, timeout time.Duration, tcfg transport.Configuration) (transport.Conn, error) {
	return nil, errors.New(unsupportedErr)
}

func (address) Listen(name string, i *identity.TokenId, acceptF func(transport.Conn), tcfg transport.Configuration) (io.Closer, error) {
	return nil, errors.New(unsupportedErr)
}

func (address) MustListen(name string, i *identity.TokenId, acceptF func(transport.Conn), tcfg transport.Configuration) io.Closer {
	panic(unsupportedErr)
}

func (a address) String() string {
	return fmt.Sprintf("%s:%s", Type, a.bindableAddress())
}

func (a address) bindableAddress() string {
	return transport.HostPortString(a.hostname, a.port)
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

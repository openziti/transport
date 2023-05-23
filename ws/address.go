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
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"io"
	"strconv"
	"strings"
	"time"
)

var _ transport.Address = &address{} // enforce that address implements transport.Address

const Type = "ws"
const unsupported_err = "transport.ws not supported. use transport.wss"

type address struct {
	hostname string
	port     uint16
}

func (address) Dial(name string, i *identity.TokenId, timeout time.Duration, tcfg transport.Configuration) (transport.Conn, error) {
	return nil, errors.New(unsupported_err)
}

func (address) DialWithLocalBinding(name string, binding string, i *identity.TokenId, timeout time.Duration, tcfg transport.Configuration) (transport.Conn, error) {
	return nil, errors.New(unsupported_err)
}

func (address) Listen(name string, i *identity.TokenId, acceptF func(transport.Conn), tcfg transport.Configuration) (io.Closer, error) {
	return nil, errors.New(unsupported_err)
}

func (address) MustListen(name string, i *identity.TokenId, acceptF func(transport.Conn), tcfg transport.Configuration) io.Closer {
	panic(unsupported_err)
}

func (a address) String() string {
	return fmt.Sprintf("%s:%s", Type, a.bindableAddress())
}

func (a address) bindableAddress() string {
	return fmt.Sprintf("%s:%d", a.hostname, a.port)
}

func (a address) Type() string {
	return Type
}

type AddressParser struct{}

func (ap AddressParser) Parse(s string) (transport.Address, error) {
	tokens := strings.Split(s, ":")
	if len(tokens) < 2 {
		return nil, errors.New("invalid format")
	}

	if tokens[0] == Type {
		if len(tokens) != 3 {
			return nil, errors.New("invalid format")
		}

		port, err := strconv.ParseUint(tokens[2], 10, 16)
		if err != nil {
			return nil, err
		}

		return &address{hostname: tokens[1], port: uint16(port)}, nil
	}

	return nil, errors.New("invalid format")
}

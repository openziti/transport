/*
	Copyright NetFoundry, Inc.

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
	"github.com/openziti/foundation/identity/identity"
	"github.com/openziti/transport"
	"io"
	"strconv"
	"strings"
	"time"
)

var _ transport.Address = (*address)(nil) // enforce that address implements transport.Address

type address struct {
	hostname string
	port     uint16
}

func (a address) Dial(name string, i *identity.TokenId, _ time.Duration, _ transport.Configuration) (transport.Connection, error) {
	return Dial(a.bindableAddress(), name)
}

func (a address) DialWithLocalBinding(name string, localBinding string, _ *identity.TokenId, timeout time.Duration, _ transport.Configuration) (transport.Connection, error) {
	return DialWithLocalBinding(a.bindableAddress(), name, localBinding)
}

func (a address) Listen(name string, i *identity.TokenId, incoming chan transport.Connection, tcfg transport.Configuration) (io.Closer, error) {
	var subc map[interface{}]interface{}
	if tcfg != nil {
		if v, found := tcfg["ws"]; found {
			if subv, ok := v.(map[interface{}]interface{}); ok {
				subc = subv
			}
		}
	}

	return Listen(a.bindableAddress(), name, incoming, subc)
}

func (a address) MustListen(name string, i *identity.TokenId, incoming chan transport.Connection, tcfg transport.Configuration) io.Closer {
	closer, err := a.Listen(name, i, incoming, tcfg)
	if err != nil {
		panic(err)
	}
	return closer
}

func (a address) String() string {
	return fmt.Sprintf("ws:%s", a.bindableAddress())
}

func (a address) bindableAddress() string {
	return fmt.Sprintf("%s:%d", a.hostname, a.port)
}

func (a address) Type() string {
	return "ws"
}

type AddressParser struct{}

func (ap AddressParser) Parse(s string) (transport.Address, error) {
	tokens := strings.Split(s, ":")
	if len(tokens) < 2 {
		return nil, errors.New("invalid format")
	}

	if tokens[0] == "ws" {
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

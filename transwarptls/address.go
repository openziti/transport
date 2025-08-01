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

package transwarptls

import (
	"fmt"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"github.com/pkg/errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

var _ transport.Address = &address{} // enforce that address implements transport.Address

type address struct {
	hostname string
	port     uint16
}

const Type = "transwarptls"

func (self address) Dial(name string, id *identity.TokenId, _ time.Duration, tcfg transport.Configuration) (transport.Conn, error) {
	endpoint, err := net.ResolveUDPAddr("udp", self.bindableAddress())
	if err != nil {
		return nil, errors.Wrap(err, "resolve udp")
	}
	var subc map[interface{}]interface{}
	if tcfg != nil {
		if v, found := tcfg["westworld3"]; found {
			if subv, ok := v.(map[interface{}]interface{}); ok {
				subc = subv
			}
		}
	}
	return Dial(endpoint, name, id, subc)
}

func (self address) DialWithLocalBinding(name string, localBinding string, id *identity.TokenId, _ time.Duration, tcfg transport.Configuration) (transport.Conn, error) {
	endpoint, err := net.ResolveUDPAddr("udp", self.bindableAddress())
	if err != nil {
		return nil, errors.Wrap(err, "resolve udp")
	}
	var subc map[interface{}]interface{}
	if tcfg != nil {
		if v, found := tcfg["westworld3"]; found {
			if subv, ok := v.(map[interface{}]interface{}); ok {
				subc = subv
			}
		}
	}
	return DialWithLocalBinding(endpoint, name, localBinding, id, subc)
}

func (self address) Listen(name string, id *identity.TokenId, acceptF func(transport.Conn), tcfg transport.Configuration) (io.Closer, error) {
	bind, err := net.ResolveUDPAddr("udp", self.bindableAddress())
	if err != nil {
		return nil, errors.Wrap(err, "resolve udp")
	}
	var subc map[interface{}]interface{}
	if tcfg != nil {
		if v, found := tcfg["westworld3"]; found {
			if subv, ok := v.(map[interface{}]interface{}); ok {
				subc = subv
			}
		}
	}
	return Listen(bind, name, id, acceptF, subc)
}

func (self address) MustListen(name string, id *identity.TokenId, acceptF func(transport.Conn), tcfg transport.Configuration) io.Closer {
	closer, err := self.Listen(name, id, acceptF, tcfg)
	if err != nil {
		panic(err)
	}
	return closer
}

func (self address) String() string {
	return fmt.Sprintf("%s:%s", Type, self.bindableAddress())
}

func (self address) bindableAddress() string {
	return fmt.Sprintf("%s:%d", self.hostname, self.port)
}

func (self address) Type() string {
	return Type
}

func (self address) Hostname() string {
	return self.hostname
}

func (self address) Port() uint16 {
	return self.port
}

type AddressParser struct{}

func (self AddressParser) Parse(s string) (transport.Address, error) {
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

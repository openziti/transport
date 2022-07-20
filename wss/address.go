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

package wss

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

const Type = "wss"

type address struct {
	hostname string
	port     uint16
}

func (a address) Dial(_ string, _ *identity.TokenId, _ time.Duration, _ transport.Configuration) (transport.Conn, error) {
	panic("Dial is unsupported for wss transport")
}

func (a address) DialWithLocalBinding(_ string, _ string, _ *identity.TokenId, _ time.Duration, _ transport.Configuration) (transport.Conn, error) {
	panic("Dial is unsupported for wss transport")
}

func (a address) Listen(name string, i *identity.TokenId, acceptF func(transport.Conn), config transport.Configuration) (io.Closer, error) {
	var wssConfig map[interface{}]interface{}
	if config != nil {
		if v, found := config["wss"]; found {
			wssConfig = v.(map[interface{}]interface{})
		}
	}

	return Listen(a.bindableAddress(), name, i, acceptF, wssConfig)
}

func (a address) MustListen(name string, i *identity.TokenId, acceptF func(transport.Conn), tcfg transport.Configuration) io.Closer {
	closer, err := a.Listen(name, i, acceptF, tcfg)
	if err != nil {
		panic(err)
	}
	return closer
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

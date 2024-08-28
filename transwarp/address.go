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

package transwarp

import (
	"fmt"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"
)

var _ transport.Address = &address{} // enforce that address implements transport.Address

const Type = "transwarp"

type address struct {
	hostname string
	port     uint16
}

func (self address) Dial(name string, _ *identity.TokenId, _ time.Duration, tcfg transport.Configuration) (transport.Conn, error) {
	endpoint, err := net.ResolveUDPAddr("udp", self.bindableAddress())
	if err != nil {
		return nil, errors.Wrap(err, "resolve udp")
	}
	subc := make(map[interface{}]interface{})
	if tcfg != nil {
		if v, found := tcfg["westworld3"]; found {
			if subv, ok := v.(map[string]interface{}); ok {
				for k, v := range subv {
					subc[k] = v
				}
			} else {
				logrus.Warn(reflect.TypeOf(v))
			}
		}
	}
	return Dial(endpoint, name, subc)
}

func (self address) DialWithLocalBinding(name string, localBinding string, _ *identity.TokenId, _ time.Duration, tcfg transport.Configuration) (transport.Conn, error) {
	endpoint, err := net.ResolveUDPAddr("udp", self.bindableAddress())
	if err != nil {
		return nil, errors.Wrap(err, "resolve udp")
	}
	subc := make(map[interface{}]interface{})
	if tcfg != nil {
		if v, found := tcfg["westworld3"]; found {
			if subv, ok := v.(map[string]interface{}); ok {
				for k, v := range subv {
					subc[k] = v
				}
			} else {
				logrus.Warn(reflect.TypeOf(v))
			}
		}
	}

	return DialWithLocalBinding(endpoint, name, localBinding, subc)
}

func (self address) Listen(name string, _ *identity.TokenId, acceptF func(transport.Conn), tcfg transport.Configuration) (io.Closer, error) {
	bind, err := net.ResolveUDPAddr("udp", self.bindableAddress())
	if err != nil {
		return nil, errors.Wrap(err, "resolve udp")
	}
	subc := make(map[interface{}]interface{})
	if tcfg != nil {
		if v, found := tcfg["westworld3"]; found {
			if subv, ok := v.(map[string]interface{}); ok {
				for k, v := range subv {
					subc[k] = v
				}
			} else {
				logrus.Warn(reflect.TypeOf(v))
			}
		}
	}
	logrus.Info(subc)
	return Listen(bind, name, acceptF, subc)
}

func (self address) MustListen(name string, i *identity.TokenId, acceptF func(transport.Conn), tcfg transport.Configuration) io.Closer {
	closer, err := self.Listen(name, i, acceptF, tcfg)
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

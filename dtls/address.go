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

package dtls

import (
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"github.com/pkg/errors"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

var _ transport.Address = &address{} // enforce that address implements transport.Address

const Type = "dtls"

type address struct {
	net.UDPAddr
	original string
	err      error
}

func (a *address) Dial(name string, i *identity.TokenId, timeout time.Duration, _ transport.Configuration) (transport.Conn, error) {
	return Dial(a, name, i, timeout)
}

func (a *address) DialWithLocalBinding(name string, localBinding string, i *identity.TokenId, timeout time.Duration, tcfg transport.Configuration) (transport.Conn, error) {
	return DialWithLocalBinding(a, name, localBinding, i, timeout)
}

func (a *address) Listen(name string, i *identity.TokenId, acceptF func(transport.Conn), tcfg transport.Configuration) (io.Closer, error) {
	return Listen(a, name, i, tcfg, acceptF)
}

func (a *address) MustListen(name string, i *identity.TokenId, acceptF func(transport.Conn), tcfg transport.Configuration) io.Closer {
	closer, err := a.Listen(name, i, acceptF, tcfg)
	if err != nil {
		panic(err)
	}
	return closer
}

func (a *address) String() string {
	return a.original
}

func (a *address) Type() string {
	return Type
}

func (a *address) withError(err error) (*address, error) {
	a.err = err
	return a, nil
}

func (a *address) Hostname() string {
	return a.UDPAddr.IP.String()
}

func (a *address) Port() uint16 {
	return uint16(a.UDPAddr.Port)
}

type AddressParser struct{}

func (ap AddressParser) Parse(s string) (transport.Address, error) {
	if !strings.HasPrefix(s, Type+":") {
		return nil, errors.Errorf("invalid dtls address '%v', doesn't start with dtls:", s)
	}

	addr := &address{
		original: s,
	}
	hostPort := s[len(Type+":"):]

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return addr.withError(errors.Wrapf(err, "unable to parse addr host and port from %v", s))
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return addr.withError(errors.Wrapf(err, "unable to parse port from %v", portStr))
	}

	if port < 0 || port > math.MaxUint16 {
		return addr.withError(errors.Wrapf(err, "invalid port value %v", portStr))
	}

	ipAddr := net.ParseIP(host)
	if ipAddr == nil {
		ips, err := net.LookupHost(host)
		if err != nil {
			return addr.withError(errors.Wrapf(err, "unable to resolve host %v", host))
		}
		if len(ips) == 0 {
			return addr.withError(errors.Wrapf(err, "no IPs found when resolving host %v", host))
		}
		ipAddr = net.ParseIP(ips[0])
	}

	addr.UDPAddr = net.UDPAddr{
		IP:   ipAddr,
		Port: port,
	}
	return addr, nil
}

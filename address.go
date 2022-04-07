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

package transport

import (
	"errors"
	"fmt"
	"github.com/openziti/foundation/identity/identity"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"time"
)

type Configuration map[interface{}]interface{}

// Address implements the functionality provided by a generic "address".
//
type Address interface {
	Dial(name string, i *identity.TokenId, timeout time.Duration, tcfg Configuration) (Connection, error)
	DialWithLocalBinding(name string, binding string, i *identity.TokenId, timeout time.Duration, tcfg Configuration) (Connection, error)
	Listen(name string, i *identity.TokenId, incoming chan Connection, tcfg Configuration) (io.Closer, error)
	MustListen(name string, i *identity.TokenId, incoming chan Connection, tcfg Configuration) io.Closer
	String() string
	Type() string
}

// AddressParser implements the functionality provided by an "address parser".
//
type AddressParser interface {
	Parse(addressString string) (Address, error)
}

// AddAddressParser adds an AddressParser to the globally-configured address parsers.
//
func AddAddressParser(addressParser AddressParser) {
	for _, e := range addressParsers {
		if addressParser == e {
			return
		}
	}
	addressParsers = append(addressParsers, addressParser)
}

// ParseAddress uses the globally-configured AddressParser instances to parse an address.
//
func ParseAddress(addressString string) (Address, error) {
	if addressParsers == nil || len(addressParsers) < 1 {
		return nil, errors.New("no configured address parsers")
	}
	for _, addressParser := range addressParsers {
		address, err := addressParser.Parse(addressString)
		if err == nil {
			return address, nil
		}
	}
	return nil, fmt.Errorf("address (%v) not parsed", addressString)
}

// The globally-configured address parsers.
//
var addressParsers = make([]AddressParser, 0)

// Resolve a network interface by name or IP address
func ResolveInterface(toResolve string) (*net.Interface, error) {
	// Easy check first - see if the interface is specified by name
	ief, err := net.InterfaceByName(toResolve)

	if err == nil {
		return ief, nil
	}

	// Nope! Scan all network interfaces to if there is an IP match
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if (iface.Flags & net.FlagUp) == 0 {
			// TODO:  Do we want to do this?  Should it be a flag to the method? Will a down interface even have an IP?
			log.Debugf("Interface %s is down, ignoring it for address resolution", iface.Name)
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			log.Warnf("Could not check interface %s (%s)", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			log.Tracef("Checking interface %s (%s) against %s", iface.Name, addr.String(), toResolve)

			var ip net.IP

			switch addr := addr.(type) {
			case *net.IPAddr:
				ip = addr.IP
			case *net.IPNet:
				ip = addr.IP
			default:
				continue
			}

			if ip.To4() != nil && ip.To4().String() == toResolve {
				log.Debugf("Resolved %s to interface %s", toResolve, iface.Name)
				return &iface, nil
			}
		}
	}

	// Not an IP either, not sure how to resolve this interface
	return nil, errors.New(fmt.Sprintf("no network interface found for %s", toResolve))
}

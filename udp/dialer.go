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

package udp

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/openziti/foundation/identity/identity"
	"github.com/openziti/transport"
	"math"
	"net"
	"time"
)

func Dial(destination *net.UDPAddr, name string, _ *identity.TokenId, timeout time.Duration) (transport.Connection, error) {
	socket, err := net.DialTimeout("udp", destination.String(), timeout)
	if err != nil {
		return nil, err
	}

	return &Connection{
		detail: &transport.ConnectionDetail{
			Address: "udp:" + destination.String(),
			InBound: false,
			Name:    name,
		},
		socket: socket,
		reader: bufio.NewReaderSize(socket, math.MaxUint16),
	}, nil
}

func DialWithLocalBinding(destination *net.UDPAddr, name, localBinding string, timeout time.Duration) (transport.Connection, error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	if localBinding != "" {
		iface, err := transport.ResolveInterface(localBinding)

		if err != nil {
			return nil, err
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		if len(addrs) == 0 {
			return nil, errors.New(fmt.Sprintf("no ip addresses assigned to interface %s", localBinding))
		}

		dialer.LocalAddr = &net.UDPAddr{
			IP: addrs[0].(*net.IPNet).IP,
		}
	}

	socket, err := dialer.Dial("udp", destination.String())

	if err != nil {
		return nil, err
	}

	return &Connection{
		detail: &transport.ConnectionDetail{
			Address: "udp:" + destination.String(),
			InBound: false,
			Name:    name,
		},
		socket: socket,
		reader: bufio.NewReaderSize(socket, math.MaxUint16),
	}, nil
}

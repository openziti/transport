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

package tcp

import (
	"github.com/openziti/transport/v2"
	"net"
	"time"
)

func Dial(destination, name string, timeout time.Duration) (transport.Conn, error) {
	socket, err := net.DialTimeout("tcp", destination, timeout)
	if err != nil {
		return nil, err
	}

	return &Connection{
		detail: &transport.ConnectionDetail{
			Address: Type + ":" + destination,
			InBound: false,
			Name:    name,
		},
		Conn: socket,
	}, nil
}

func DialWithLocalBinding(destination, name, localBinding string, timeout time.Duration) (transport.Conn, error) {

	dialer, err := transport.NewDialerWithLocalBinding(Type, timeout, localBinding)

	if err != nil {
		return nil, err
	}

	socket, err := dialer.Dial("tcp", destination)

	if err != nil {
		return nil, err
	}

	return &Connection{
		detail: &transport.ConnectionDetail{
			Address: Type + ":" + destination,
			InBound: false,
			Name:    name,
		},
		Conn: socket,
	}, nil
}

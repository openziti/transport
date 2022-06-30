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

package dtls

import (
	"context"
	"crypto/tls"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"github.com/pion/dtls/v2"
	"net"
	"time"
)

func Dial(addr *address, name string, i *identity.TokenId, timeout time.Duration) (transport.Conn, error) {
	return DialWithLocalBinding(addr, name, "", i, timeout)
}

func DialWithLocalBinding(addr *address, name, localBinding string, i *identity.TokenId, timeout time.Duration) (transport.Conn, error) {
	if addr.err != nil {
		return nil, addr.err
	}
	ip, err := transport.ResolveLocalBinding(localBinding)
	if err != nil {
		return nil, err
	}

	log := pfxlog.Logger()

	cfg := &dtls.Config{
		Certificates: []tls.Certificate{*i.Cert()},
		//ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		RootCAs: i.CA(),
	}

	var localAddr *net.UDPAddr
	if ip != nil {
		localAddr = &net.UDPAddr{IP: ip}
	}

	udpConn, err := net.DialUDP("udp", localAddr, &addr.UDPAddr)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	cancelF := func() {}
	if timeout > 0 {
		ctx, cancelF = context.WithTimeout(ctx, timeout)
	}
	conn, err := dtls.ClientWithContext(ctx, udpConn, cfg)
	cancelF()
	if err != nil {
		return nil, err
	}

	log.Debugf("server provided [%d] certificates", len(conn.ConnectionState().PeerCertificates))

	certs, err := getPeerCerts(conn)
	if err != nil {
		return nil, err
	}

	return &Connection{
		detail: &transport.ConnectionDetail{
			Address: addr.String(),
			InBound: false,
			Name:    name,
		},
		Conn:  conn,
		certs: certs,
	}, nil
}

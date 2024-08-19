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
	"context"
	"crypto/tls"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"github.com/pion/dtls/v3"
	"github.com/pkg/errors"
	"net"
	"time"
)

func Dial(addr *address, name string, i *identity.TokenId, timeout time.Duration) (transport.Conn, error) {
	return DialWithLocalBinding(addr, name, "", i, timeout)
}

func DialWithLocalBinding(addr *address, name, localBinding string, i *identity.TokenId, timeout time.Duration) (transport.Conn, error) {
	log := pfxlog.Logger()
	log.WithField("address", addr.String()).Debug("dialing")

	if addr.err != nil {
		return nil, addr.err
	}
	ip, closeErr := transport.ResolveLocalBinding(localBinding)
	if closeErr != nil {
		return nil, closeErr
	}

	cfg := &dtls.Config{
		Certificates: []tls.Certificate{*i.Cert()},
		//ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		RootCAs: i.CA(),
	}

	var localAddr *net.UDPAddr
	if ip != nil {
		localAddr = &net.UDPAddr{IP: ip}
	}

	udpConn, closeErr := net.ListenUDP("udp", localAddr)
	if closeErr != nil {
		return nil, closeErr
	}

	conn, closeErr := dtls.Client(udpConn, &addr.UDPAddr, cfg)
	if closeErr != nil {
		return nil, closeErr
	}

	ctx := context.Background()
	cancelF := func() {}
	if timeout > 0 {
		ctx, cancelF = context.WithTimeout(ctx, timeout)
	}
	closeErr = conn.HandshakeContext(ctx)
	cancelF()
	if closeErr != nil {
		if closeErr := conn.Close(); closeErr != nil {
			log.WithError(closeErr).Error("error closing connection")
		}
		return nil, errors.Wrap(closeErr, "dtls handshake error")
	}

	certs, closeErr := getPeerCerts(conn)
	if closeErr != nil {
		if closeErr = conn.Close(); closeErr != nil {
			log.WithError(closeErr).Error("error closing connection")
		}
		return nil, errors.Wrap(closeErr, "error getting peer certificates")
	}

	log.Debugf("server provided [%d] certificates", len(certs))

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

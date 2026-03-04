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
	"fmt"
	"io"
	"net"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"github.com/openziti/transport/v2/shaper"
	"github.com/pion/dtls/v3"
	"github.com/pkg/errors"
)

const (
	DefaultBufferSize = 4 * 1024 * 1024
)

func Dial(addr *address, name string, i *identity.TokenId, timeout time.Duration, tcfg transport.Configuration) (transport.Conn, error) {
	return DialWithLocalBinding(addr, name, "", i, timeout, tcfg)
}

func DialWithLocalBinding(addr *address, name, localBinding string, i *identity.TokenId, timeout time.Duration, tcfg transport.Configuration) (transport.Conn, error) {
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

	writeBufferSize := DefaultBufferSize
	bufferSize, found, err := tcfg.GetUIntValue("dtls", "writeBufferSize")
	if err != nil {
		return nil, err
	}
	if found {
		writeBufferSize = int(bufferSize)
	}
	if err := udpConn.SetWriteBuffer(writeBufferSize); err != nil {
		return nil, fmt.Errorf("unable to set udp write buffer size to %d (%w)", writeBufferSize, err)
	}

	readBufferSize := DefaultBufferSize
	bufferSize, found, err = tcfg.GetUIntValue("dtls", "readBufferSize")
	if err != nil {
		return nil, err
	}
	if found {
		readBufferSize = int(bufferSize)
	}
	if err = udpConn.SetWriteBuffer(readBufferSize); err != nil {
		return nil, fmt.Errorf("unable to set udp read buffer size to %d (%w)", readBufferSize, err)
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

	var w io.Writer = conn
	bps, found, err := tcfg.GetInt64Value("dtls", "maxBytesPerSecond")
	if err != nil {
		return nil, err
	}
	if found {
		log.Infof("limiting DTLS writes to %dB/s", bps)
		w = shaper.LimitWriter(conn, time.Second, bps)
	}

	return &Connection{
		detail: &transport.ConnectionDetail{
			Address: addr.String(),
			InBound: false,
			Name:    name,
		},
		Conn:  conn,
		certs: certs,
		w:     w,
	}, nil
}

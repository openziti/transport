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
	ip, err := transport.ResolveLocalBinding(localBinding)
	if err != nil {
		return nil, err
	}

	var localAddr *net.UDPAddr
	if ip != nil {
		localAddr = &net.UDPAddr{IP: ip}
	}

	udpConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, err
	}

	closeUdpConn := true
	defer func() {
		if closeUdpConn {
			if closeErr := udpConn.Close(); closeErr != nil {
				log.WithError(closeErr).Error("error closing udp connection")
			}
		}
	}()

	writeBufferSize := DefaultBufferSize
	bufferSize, found, err := tcfg.GetUIntValue("dtls", "writeBufferSize")
	if err != nil {
		return nil, err
	}
	if found {
		writeBufferSize = int(bufferSize)
	}

	if err = udpConn.SetWriteBuffer(writeBufferSize); err != nil {
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
	if err = udpConn.SetReadBuffer(readBufferSize); err != nil {
		return nil, fmt.Errorf("unable to set udp read buffer size to %d (%w)", readBufferSize, err)
	}

	conn, err := dtls.ClientWithOptions(udpConn, &addr.UDPAddr,
		dtls.WithCertificates(*i.Cert()),
		dtls.WithRootCAs(i.CA()),
	)
	if err != nil {
		return nil, err
	}

	// from here on, closing conn will also close udpConn
	closeUdpConn = false
	closeConn := true
	defer func() {
		if closeConn {
			if closeErr := conn.Close(); closeErr != nil {
				log.WithError(closeErr).Error("error closing dtls connection")
			}
		}
	}()

	ctx := context.Background()
	cancelF := func() {}
	if timeout > 0 {
		ctx, cancelF = context.WithTimeout(ctx, timeout)
	}
	err = conn.HandshakeContext(ctx)
	cancelF()
	if err != nil {
		return nil, fmt.Errorf("dtls handshake error: %w", err)
	}

	certs, err := getPeerCerts(conn)
	if err != nil {
		return nil, errors.Wrap(err, "error getting peer certificates")
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

	closeConn = false
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

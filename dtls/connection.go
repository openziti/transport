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
	"crypto/x509"
	"github.com/openziti/transport/v2"
	"github.com/pion/dtls/v3"
	"github.com/pkg/errors"
)

func getPeerCerts(conn *dtls.Conn) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	connState, ok := conn.ConnectionState()
	if !ok {
		return nil, errors.New("unable to get dtls connection state, couldn't get peer certificates")
	}
	for _, certBytes := range connState.PeerCertificates {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, errors.Wrap(err, "couldn't parse peer cert")
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

type Connection struct {
	detail *transport.ConnectionDetail
	*dtls.Conn
	certs []*x509.Certificate
}

func (self *Connection) Detail() *transport.ConnectionDetail {
	return self.detail
}

func (self *Connection) PeerCertificates() []*x509.Certificate {
	return self.certs
}

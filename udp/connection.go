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

package udp

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"github.com/openziti/transport/v2"
	"github.com/pkg/errors"
	"io"
	"net"
)

type Connection struct {
	detail *transport.ConnectionDetail
	net.Conn
	reader io.Reader
}

func (self *Connection) Detail() *transport.ConnectionDetail {
	return self.detail
}

func (self *Connection) PeerCertificates() []*x509.Certificate {
	return nil
}

func (self *Connection) Read(p []byte) (n int, err error) {
	return self.reader.Read(p)
}

type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Wrote: %v byte to underlay\n", len(b))
	if n, err := w.Writer.Write(b); err != nil {
		panic(err)
	} else {
		return n, nil
	}
}

type loggingReader struct{ io.Reader }

func (w loggingReader) Read(b []byte) (int, error) {
	n, err := w.Reader.Read(b)
	if err != nil {
		return n, err
	}
	fmt.Printf("Read: %v bytes from underlay\n", n)
	magicV2 := []byte{0x03, 0x06, 0x09, 0x0c}
	if len(b) > 20 && bytes.Equal(magicV2, b[:4]) {
		panic(errors.New("no good"))
	}
	return n, err
}

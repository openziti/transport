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

package ws

import (
	"github.com/gorilla/websocket"
	"net"
	"time"
)

type connImpl struct {
	ws       *websocket.Conn
	leftover []byte
}

func (self *connImpl) Read(b []byte) (int, error) {
	if len(self.leftover) > 0 {
		n := copy(b, self.leftover)
		self.leftover = self.leftover[n:]
		return n, nil
	}

	_, buf, err := self.ws.ReadMessage()
	if err != nil {
		return 0, err
	}

	n := copy(buf, self.leftover)
	self.leftover = buf[n:]
	return n, nil
}

func (self *connImpl) Write(b []byte) (int, error) {
	if err := self.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (self *connImpl) Close() error {
	return self.ws.Close()
}

func (self *connImpl) LocalAddr() net.Addr {
	return self.ws.LocalAddr()
}

func (self *connImpl) RemoteAddr() net.Addr {
	return self.ws.RemoteAddr()
}

func (self *connImpl) SetDeadline(t time.Time) error {
	return self.ws.SetReadDeadline(t)
}

func (self *connImpl) SetReadDeadline(t time.Time) error {
	return self.ws.SetReadDeadline(t)
}

func (self *connImpl) SetWriteDeadline(t time.Time) error {
	return self.ws.SetWriteDeadline(t)
}

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

package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

func Listen(bindAddress, name string, i *identity.TokenId, acceptF func(transport.Conn), protocols ...string) (io.Closer, error) {
	//log := pfxlog.ContextLogger(name + "/" + Type + ":" + bindAddress).Entry

	config := i.ServerTLSConfig().Clone()
	if len(protocols) > 0 {
		config.NextProtos = append(config.NextProtos, protocols...)
	}
	result := &acceptor{
		name:    name,
		tls:     config,
		acceptF: acceptF,
	}

	err := registerWithSharedListener(bindAddress, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

type acceptor struct {
	name     string
	listener *sharedListener
	tls      *tls.Config
	acceptF  func(conn transport.Conn)
	closed   atomic.Bool
}

func (self *acceptor) Close() error {
	if self.closed.CompareAndSwap(false, true) {
		self.listener.remove(self)
		return nil
	}
	return nil
}

//func (self *acceptor) acceptLoop(log *logrus.Entry) {
//	defer log.Info("exited")
//
//	for !self.closed.Load() {
//		socket, err := self.listener.Accept()
//		if err != nil {
//			if self.closed.Load() {
//				log.WithField("err", err).Info("listener closed, exiting")
//				return
//			}
//			log.WithField("err", err).Error("accept failed. Failure not recoverable. Exiting listen loop")
//			return
//		} else {
//			connection := &Connection{
//				detail: &transport.ConnectionDetail{
//					Address: Type + ":" + socket.RemoteAddr().String(),
//					InBound: true,
//					Name:    self.name,
//				},
//				Conn: socket.(*tls.Conn),
//			}
//			self.acceptF(connection)
//		}
//	}
//}

var sharedListeners sync.Map

func init() {
}

func registerWithSharedListener(bindAddress string, acc *acceptor) error {
	sl := &sharedListener{
		address: bindAddress,
	}
	sl.tlsCfg = &tls.Config{
		GetConfigForClient: sl.getConfig,
	}

	el, found := sharedListeners.LoadOrStore(bindAddress, sl)
	sl = el.(*sharedListener)

	if !found {
		sl.acceptors = make(map[string]*acceptor)
		sock, err := tls.Listen("tcp", bindAddress, sl.tlsCfg)
		if err != nil {
			sharedListeners.Delete(bindAddress)
			return err
		}
		sl.sock = sock
		go sl.runAccept()
	}

	protos := acc.tls.NextProtos
	if protos == nil {
		protos = append(protos, "")
	}

	// check for conflict
	for _, proto := range protos {
		if _, exists := sl.acceptors[proto]; exists {
			return fmt.Errorf("handler for protocol[%s] already exists", proto)
		}
	}

	acc.listener = sl
	for _, proto := range protos {
		sl.acceptors[proto] = acc
	}

	return nil
}

type sharedListener struct {
	address   string
	tlsCfg    *tls.Config
	acceptors map[string]*acceptor // proto -> acceptor
	ctx       context.Context
	sock      net.Listener
}

func (self *sharedListener) runAccept() {
	for {
		c, err := self.sock.Accept()
		if err != nil {
			return
		}

		conn := c.(*tls.Conn)
		err = conn.Handshake()
		if err != nil {
			_ = conn.Close()
			continue
		}

		proto := conn.ConnectionState().NegotiatedProtocol

		acc, found := self.acceptors[proto]
		if found {
			connection := &Connection{
				detail: &transport.ConnectionDetail{
					Address: Type + ":" + conn.RemoteAddr().String(),
					InBound: true,
					Name:    acc.name,
				},
				Conn: conn,
			}
			acc.acceptF(connection)
		} else {
			_ = conn.Close()
		}
	}
}

func (self *sharedListener) getConfig(info *tls.ClientHelloInfo) (*tls.Config, error) {
	protos := info.SupportedProtos
	if protos == nil {
		protos = append(protos, "")
	}

	for _, proto := range protos {
		acc, found := self.acceptors[proto]
		if found {
			cfg := acc.tls
			if cfg.GetConfigForClient != nil {
				c, _ := cfg.GetConfigForClient(info)
				if c != nil {
					return c, nil
				}
			}
			return cfg, nil
		}
	}

	return nil, fmt.Errorf("not handler for requested protocols %+v", protos)
}

func (self *sharedListener) remove(acc *acceptor) {
	if len(acc.tls.NextProtos) == 0 {
		delete(self.acceptors, "")
	} else {
		for _, p := range acc.tls.NextProtos {
			delete(self.acceptors, p)
		}
	}
	if len(self.acceptors) == 0 {
		sharedListeners.Delete(self.address)
		_ = self.sock.Close()
	}
}

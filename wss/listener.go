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

package wss

import (
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"github.com/openziti/transport/v2/ws"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
)

var upgrader = websocket.Upgrader{}

type wssListener struct {
	log     *logrus.Entry
	acceptF func(transport.Conn)
	cfg     *ws.Config
}

/**
 *	Accept acceptF HTTP connection, and upgrade it to a websocket suitable for comms between browZer and Ziti Edge Router
 */
func (listener *wssListener) handleWebsocket(w http.ResponseWriter, r *http.Request) {
	log := listener.log
	log.Info("entered")

	c, err := upgrader.Upgrade(w, r, nil) // upgrade from HTTP to binary socket

	if err != nil {
		log.WithField("err", err).Error("websocket upgrade failed. Failure not recoverable.")
	} else {

		connection := &Connection{
			detail: &transport.ConnectionDetail{
				Address: "wss:" + c.UnderlyingConn().RemoteAddr().String(),
				InBound: true,
				Name:    "wss",
			},
			ws:    c,
			log:   log,
			rxbuf: newSafeBuffer(log),
			txbuf: newSafeBuffer(log),
			done:  make(chan struct{}),
			cfg:   listener.cfg,
		}

		go connection.pinger()

		listener.acceptF(connection) // pass the Websocket to the goroutine that will validate the HELLO handshake
	}
}
func Listen(bindAddress, name string, i *identity.TokenId, acceptF func(transport.Conn), transportConfig transport.Configuration) (io.Closer, error) {
	log := pfxlog.ContextLogger(name + "/wss:" + bindAddress)

	config := ws.NewDefaultConfig()
	config.Identity = i

	if transportConfig != nil {
		if err := config.Load(transportConfig); err != nil {
			return nil, errors.Wrap(err, "load configuration")
		}
	}
	logrus.Infof(config.Dump("wss.Config"))

	go startHttpServer(log.Entry, bindAddress, config, name, acceptF)

	return nil, nil
}

// startHttpServer will start an HTTP server that will upgrade to WebSocket connections on request
func startHttpServer(log *logrus.Entry, bindAddress string, config *ws.Config, name string, acceptF func(transport.Conn)) {

	log.Infof("starting HTTP (websocket) server at bindAddress [%s]", bindAddress)

	listener := &wssListener{
		log:     log,
		acceptF: acceptF,
		cfg:     config,
	}

	// Set up the HTTP -> Websocket upgrader options (once, before we start listening)
	upgrader.HandshakeTimeout = config.HandshakeTimeout
	upgrader.ReadBufferSize = config.ReadBufferSize
	upgrader.WriteBufferSize = config.WriteBufferSize
	upgrader.EnableCompression = config.EnableCompression
	upgrader.CheckOrigin = func(r *http.Request) bool { return true } // Allow all origins

	router := mux.NewRouter()

	router.HandleFunc("/wss", listener.handleWebsocket).Methods("GET")

	httpServer := &http.Server{
		Addr:         bindAddress,
		WriteTimeout: config.WriteTimeout,
		ReadTimeout:  config.ReadTimeout,
		IdleTimeout:  config.IdleTimeout,
		Handler:      router,
		TLSConfig:    config.Identity.ServerTLSConfig(),
	}

	if err := httpServer.ListenAndServeTLS("", ""); err != nil {
		panic(err)
	}
}

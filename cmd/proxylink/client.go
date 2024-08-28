package main

import (
	"github.com/openziti/transport/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"time"
)

func init() {
	rootCmd.AddCommand(newClientCommand().cmd)
}

type clientCommand struct {
	cmd *cobra.Command
}

func newClientCommand() *clientCommand {
	cmd := &cobra.Command{
		Use:  "client <listenAddress> <serverAddress>",
		Args: cobra.ExactArgs(2),
	}
	command := &clientCommand{cmd: cmd}
	cmd.Run = command.run
	return command
}

var serverAddress transport.Address

func (cmd *clientCommand) run(_ *cobra.Command, args []string) {
	listenAddress, err := transport.ParseAddress(args[0])
	if err != nil {
		panic(err)
	}

	serverAddress, err = transport.ParseAddress(args[1])
	if err != nil {
		panic(err)
	}

	listenAddress.MustListen("client", nil, cmd.accept, transport.Configuration{})

	for {
		time.Sleep(24 * time.Hour)
	}
}

func (cmd *clientCommand) accept(txConn transport.Conn) {
	defer txConn.Close()

	rxConn, err := serverAddress.Dial("server", nil, 30*time.Second, transport.Configuration{})
	if err != nil {
		logrus.Errorf("unable to dial '%v': %v", serverAddress, err)
		return
	}
	defer rxConn.Close()

	go sender(rxConn, txConn)
	sender(txConn, rxConn)
}

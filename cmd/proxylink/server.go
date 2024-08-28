package main

import (
	"github.com/openziti/transport/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"time"
)

func init() {
	rootCmd.AddCommand(newServerCommand().cmd)
}

type serverCommand struct {
	cmd *cobra.Command
}

func newServerCommand() *serverCommand {
	cmd := &cobra.Command{
		Use:  "server <listenAddress> <endpointAddress>",
		Args: cobra.ExactArgs(2),
	}
	command := &serverCommand{cmd: cmd}
	cmd.Run = command.run
	return command
}

var endpointAddress transport.Address

func (cmd *serverCommand) run(_ *cobra.Command, args []string) {
	listenAddress, err := transport.ParseAddress(args[0])
	if err != nil {
		panic(err)
	}

	endpointAddress, err = transport.ParseAddress(args[1])
	if err != nil {
		panic(err)
	}

	listenAddress.MustListen("server", nil, cmd.accept, transport.Configuration{})

	for {
		time.Sleep(24 * time.Hour)
	}
}

func (cmd *serverCommand) accept(txConn transport.Conn) {
	defer txConn.Close()

	rxConn, err := endpointAddress.Dial("endpoint", nil, 30*time.Second, transport.Configuration{})
	if err != nil {
		logrus.Errorf("unable to dial '%v': %v", endpointAddress, err)
		return
	}
	defer rxConn.Close()

	go sender(rxConn, txConn)
	sender(txConn, rxConn)
}

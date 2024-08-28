package main

import (
	"github.com/openziti/transport/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"os"
	"time"
)

func init() {
	rootCmd.AddCommand(newClientCommand().cmd)
}

type clientCommand struct {
	cmd        *cobra.Command
	configFile string
}

func newClientCommand() *clientCommand {
	cmd := &cobra.Command{
		Use:  "client <listenAddress> <serverAddress>",
		Args: cobra.ExactArgs(2),
	}
	command := &clientCommand{cmd: cmd}
	cmd.Flags().StringVarP(&command.configFile, "config", "c", "", "configuration file path")
	cmd.Run = command.run
	return command
}

var serverAddress transport.Address
var tcfg transport.Configuration

func (cmd *clientCommand) run(_ *cobra.Command, args []string) {
	if cmd.configFile != "" {
		inBytes, err := os.ReadFile(cmd.configFile)
		if err != nil {
			panic(err)
		}
		if err := yaml.Unmarshal(inBytes, &tcfg); err != nil {
			panic(err)
		}
	}

	listenAddress, err := transport.ParseAddress(args[0])
	if err != nil {
		panic(err)
	}

	serverAddress, err = transport.ParseAddress(args[1])
	if err != nil {
		panic(err)
	}

	listenAddress.MustListen("client", nil, cmd.accept, tcfg)

	for {
		time.Sleep(24 * time.Hour)
	}
}

func (cmd *clientCommand) accept(txConn transport.Conn) {
	defer txConn.Close()

	rxConn, err := serverAddress.Dial("server", nil, 30*time.Second, tcfg)
	if err != nil {
		logrus.Errorf("unable to dial '%v': %v", serverAddress, err)
		return
	}
	defer rxConn.Close()

	go sender(rxConn, txConn)
	sender(txConn, rxConn)
}

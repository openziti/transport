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
	rootCmd.AddCommand(newServerCommand().cmd)
}

type serverCommand struct {
	cmd        *cobra.Command
	configFile string
}

func newServerCommand() *serverCommand {
	cmd := &cobra.Command{
		Use:  "server <listenAddress> <endpointAddress>",
		Args: cobra.ExactArgs(2),
	}
	command := &serverCommand{cmd: cmd}
	cmd.Flags().StringVarP(&command.configFile, "config", "c", "", "configuration file path")
	cmd.Run = command.run
	return command
}

var endpointAddress transport.Address

func (cmd *serverCommand) run(_ *cobra.Command, args []string) {
	if cmd.configFile != "" {
		inBytes, err := os.ReadFile(cmd.configFile)
		if err != nil {
			panic(err)
		}
		if err := yaml.Unmarshal(inBytes, &tcfg); err != nil {
			panic(err)
		}
	}
	logrus.Info(tcfg)

	listenAddress, err := transport.ParseAddress(args[0])
	if err != nil {
		panic(err)
	}

	endpointAddress, err = transport.ParseAddress(args[1])
	if err != nil {
		panic(err)
	}

	listenAddress.MustListen("server", nil, cmd.accept, tcfg)

	for {
		time.Sleep(24 * time.Hour)
	}
}

func (cmd *serverCommand) accept(txConn transport.Conn) {
	defer txConn.Close()

	rxConn, err := endpointAddress.Dial("endpoint", nil, 30*time.Second, tcfg)
	if err != nil {
		logrus.Errorf("unable to dial '%v': %v", endpointAddress, err)
		return
	}
	defer rxConn.Close()

	go sender(rxConn, txConn)
	sender(txConn, rxConn)
}

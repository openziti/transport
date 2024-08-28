package main

import (
	"github.com/openziti/transport/v2"
	"github.com/sirupsen/logrus"
)

func sender(in transport.Conn, out transport.Conn) {
	defer in.Close()
	defer out.Close()

	buffer := make([]byte, 102400)
	for {
		inN, err := in.Read(buffer)
		if err != nil {
			logrus.Errorf("error reading from '%v': %v", in.LocalAddr(), err)
			return
		}
		outN, err := out.Write(buffer[:inN])
		if err != nil {
			logrus.Errorf("error writing to '%v': %v", out.LocalAddr(), err)
			return
		}
		if outN != inN {
			logrus.Errorf("short write ('%v' -> '%v')", in.LocalAddr(), out.LocalAddr())
			return
		}
	}
}

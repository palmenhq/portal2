package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

var isVerbose = false

func printInfoln(format string, a ...interface{}) {
	fmt.Println(fmt.Sprintf(format, a...))
}

func printVerboseln(format string, a ...interface{}) {
	if !isVerbose {
		return
	}
	fmt.Println(fmt.Sprintf(format, a...))
}

func printErrorln(format string, a ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, a...))
}

const helloLength = 5

func assertConnHello(conn io.Reader) error {
	helloMaybe := make([]byte, helloLength)
	_, err := conn.Read(helloMaybe)
	if err != nil {
		return fmt.Errorf("error reading hello: %s", err)
	}
	if string(helloMaybe) != "hello" {
		return fmt.Errorf("unexpected hello, received \"%s\", closing connection", helloMaybe)
	}

	printVerboseln("received hello")

	return nil
}

func int2UintByteArray(input int) []byte {
	num := make([]byte, 8)
	binary.BigEndian.PutUint32(num, uint32(input))
	return num
}

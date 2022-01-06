package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
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

func writeBase64Line(writer io.Writer, line []byte) (int, error) {
	val := bytes.Join([][]byte{encodeBase64(line), newlineByteArray}, []byte{})
	return writer.Write(val)
}

func readBase64Line(connReader *bufio.Reader) ([]byte, error) {
	base64Line, _, err := connReader.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("error reading line: %s", err)
	}

	line := make([]byte, base64.RawStdEncoding.DecodedLen(len(base64Line)))
	_, err = base64.RawStdEncoding.Decode(line, base64Line)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64: %s", err)
	}

	return line, nil
}

const helloLength = 5

func assertConnHello(conn *bufio.Reader) error {
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

func encodeBase64(input []byte) []byte {
	result := make([]byte, base64.RawStdEncoding.EncodedLen(len(input)))
	base64.RawStdEncoding.Encode(result, input)

	return result
}

func decodeBase64(input []byte) ([]byte, error) {
	result := make([]byte, base64.RawStdEncoding.DecodedLen(len(input)))
	_, err := base64.RawStdEncoding.Decode(result, input)
	if err != nil {
		return nil, err
	}

	return result, nil
}

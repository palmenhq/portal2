package main

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"
)

type mockConn struct {
	net.Conn
}

var interceptedMockConnWriteBytes []byte

func (mc mockConn) Write(b []byte) (int, error) {
	interceptedMockConnWriteBytes = b
	return len(b), nil
}

func Test_connWriteLine(t *testing.T) {
	conn := mockConn{}
	input := []byte("howdy")
	_, err := connWriteLine(conn, input)

	if err != nil {
		t.Errorf("error writing conection line: %s", err)
	}

	if !bytes.Equal(interceptedMockConnWriteBytes, bytes.Join([][]byte{input, []byte("\n")}, []byte(""))) {
		t.Errorf("expected intercepted bytes %s to equal input %s", interceptedMockConnWriteBytes, input)
	}
}

func Test_assertConnHello(t *testing.T) {
	okConnReader := bufio.NewReader(strings.NewReader("hello\n"))
	 err := assertConnHello(okConnReader)
	 if err != nil {
	 	t.Errorf("expected hello to be ok, but got error %s", err)
	 }

	invalidHelloConnReader := bufio.NewReader(strings.NewReader("not hello"))
	err = assertConnHello(invalidHelloConnReader)
	if err == nil {
		t.Error("expected invalid hello to give error but got nil")
	}
	if !strings.Contains(err.Error(), "unexpected hello") {
		t.Errorf("expected invalid hello error to contain \"unexpected hello\" but got \"%s\"", err)
	}
}

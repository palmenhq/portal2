package main

import (
	"bufio"
	"strings"
	"testing"
)

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

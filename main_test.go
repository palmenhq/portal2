package main

import (
	"strings"
	"testing"
)

func Test_assertConnHello(t *testing.T) {
	okConnReader := strings.NewReader("hello")
	 err := assertConnHello(okConnReader)
	 if err != nil {
	 	t.Errorf("expected hello to be ok, but got error %s", err)
	 }

	invalidHelloConnReader := strings.NewReader("not hello")
	err = assertConnHello(invalidHelloConnReader)
	if err == nil {
		t.Error("expected invalid hello to give error but got nil")
	}
	if !strings.Contains(err.Error(), "unexpected hello") {
		t.Errorf("expected invalid hello error to contain \"unexpected hello\" but got \"%s\"", err)
	}
}

package main

import (
	"bufio"
	"bytes"
	"testing"
)

func Test_printErrorln(t *testing.T) {
	printErrorln("howdy %s", "world")
}

func Test_writeBase64Line(t *testing.T) {
	input := []byte("howdy")
	buf := bytes.NewBuffer([]byte{})
	_, err := writeBase64Line(buf, input)

	if err != nil {
		t.Errorf("error writing conection line: %s", err)
	}

	expectedResult := bytes.Join([][]byte{encodeBase64(input), []byte("\n")}, []byte{})
	if !bytes.Equal(buf.Bytes(), expectedResult) {
		t.Errorf("expected result %s to equal %s", buf, expectedResult)
	}
}

func Test_readBase64Line(t *testing.T) {
	input := bytes.Join([][]byte{encodeBase64([]byte("howdy")), []byte("\n")}, []byte{})
	buf := bytes.NewBuffer(input)
	result, err := readBase64Line(bufio.NewReader(buf))
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(result, []byte("howdy")) {
		t.Errorf("expected result %s to be howdy", result)
	}
}

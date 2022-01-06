package main

import (
	"encoding/binary"
	"testing"
)

func Test_printErrorln(t *testing.T) {
	printErrorln("howdy %s", "world")
}

func Test_int2UintByteArray(t *testing.T) {
	a := int2UintByteArray(1337)
	result := binary.BigEndian.Uint32(a)
	if result != 1337 {
		t.Errorf("expected result %d to be 1337", result)
	}
}

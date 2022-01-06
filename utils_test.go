package main

import "testing"

func Test_printErrorln(t *testing.T) {
	printErrorln("howdy %s", "world")
}

package main

import (
	"fmt"
	"os"
)

func printErrorln(message string, stringInterpolations ...interface{}) {
	fmt.Fprintf(os.Stderr, fmt.Sprintf("%s\n",message ), stringInterpolations...)
}
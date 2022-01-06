package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/akamensky/argparse"
	"net"
	"os"
)

func main() {
	parser := argparse.NewParser("portal2", "Share secrets safely e2e")

	listenCommand := parser.NewCommand("listen", "Listen for incoming messages")
	listenPort := listenCommand.Int("p", "port", &argparse.Options{})

	//sendCommand := parser.NewCommand("send", "Send a message")
	//sendTarget := sendCommand.

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Fprint(os.Stderr, parser.Usage(err))
	}

	if listenCommand.Happened() {
		Listen(*listenPort)
	}
}

func Listen(port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		panic(err)
	}

	for {
		connection, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error accepting connection: %s", err)
		} else {
			fmt.Printf("accepted new connection from %s", connection.RemoteAddr())
			go handleListenConnection(connection)
		}
	}
}

var newlineByteArray = []byte("\n")

func handleListenConnection(conn net.Conn) {
	defer conn.Close()

	connReader := bufio.NewReader(conn)

	err := writeHello(conn)
	if err != nil {
		printErrorln(err.Error())
		return
	}

	err = assertConnHello(connReader)
	if err != nil {
		printErrorln(err.Error())
		return
	}

	//nonce := GenerateNonce()
	//privateKey, err := generateCurve25519PrivateKey()
	//if err != nil {
	//	fmt.Fprintf(os.Stderr, "error generating ec private key: %s\n", err)
	//	return
	//}
	//publicKey, err := deriveCurve25519PublicKey(privateKey)
	//if err != nil {
	//	fmt.Fprintf(os.Stderr, "error generating ec public key: %s\n", err)
	//	return
	//}
	//
	//_, err = connWriteLine(connection, bytes.Join([][]byte{nonce, publicKey, []byte("")}, newlineByteArray))
	//if err != nil {
	//	fmt.Fprintf(os.Stderr, "error sending nonce: %s\n", err)
	//	return
	//}
}

func Send(message []byte, target string) {
	conn, err := net.Dial("tcp", target)
	if err != nil {
		printErrorln("unable to dial %s: %s\n", target, err)
		return
	}
	defer conn.Close()

	connReader := bufio.NewReader(conn)

	err = assertConnHello(connReader)
	if err != nil {
		printErrorln(err.Error())
		return
	}

	err = writeHello(conn)
	if err != nil {
		printErrorln(err.Error())
		return
	}
}

func connWriteLine(connection net.Conn, line []byte) (int, error) {
	return connection.Write(bytes.Join([][]byte{line, newlineByteArray}, []byte("")))
}

func assertConnHello(connReader *bufio.Reader) error {
	helloMaybe, _, err := connReader.ReadLine()
	if err != nil {
		return fmt.Errorf("error reading hello: %s", err)
	}
	if string(helloMaybe) != "hello" {
		return fmt.Errorf("unexpected hello, received \"%s\", closing connection", helloMaybe)
	}

	return nil
}

func writeHello(conn net.Conn) error {
	_, err := connWriteLine(conn, []byte("hello"))
	if err != nil {
		return fmt.Errorf("error writing hello: %s, closing connection\n", err)
	}
	return nil
}

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/urfave/cli/v2"
	"io"
	"net"
	"os"
)

func main() {
	app := &cli.App{
		Name:  "portal2",
		Usage: "p2p messaging with e2e encryption",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Value:   false,
			},
		},
		Before: func(ctx *cli.Context) error {
			if ctx.Bool("verbose") {
				isVerbose = true
			}

			return nil
		},
		Commands: []*cli.Command{
			{
				Name: "listen",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:    "port",
						Aliases: []string{"p"},
						Value:   1337,
						Usage:   "port to listen on",
					},
				},
				Action: func(ctx *cli.Context) error {
					return Listen(ctx.Int("port"))
				},
			},
			{
				Name:      "send",
				ArgsUsage: "<target>",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() == 0 {
						return fmt.Errorf("no target address provided (expected i.e. \"127.0.0.1:1337\")")
					}

					targetAddress := ctx.Args().First()
					var stdinBytes []byte
					_, err := os.Stdin.Read(stdinBytes)
					if err != nil {
						return err
					}

					return Send(stdinBytes, targetAddress)
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		printErrorln(err.Error())
		os.Exit(1)
	}
}

func Listen(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		panic(err)
	}

	printInfoln("accepting incoming connections on port %d", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("error accepting connection: %s", err)
		} else {
			printInfoln("---\naccepted new connection from %s", conn.RemoteAddr())
			go handleListenConnection(conn)
		}
	}
}

var newlineByteArray = []byte("\n")

func handleListenConnection(conn net.Conn) {
	defer conn.Close()
	defer printInfoln("connection closed")

	connReader := bufio.NewReader(conn)

	err := writeHello(conn.(io.Writer))
	if err != nil {
		printErrorln(err.Error())
		return
	}

	err = assertConnHello(connReader)
	if err != nil {
		printErrorln(err.Error())
		return
	}

	printVerboseln("generating transaction keys")
	privateKey, thisPublicKey, err := generateTransactionKeys()
	if err != nil {
		printErrorln(err.Error())
		return
	}

	printVerboseln("sending public key \"%x\"", thisPublicKey)
	_, err = writeBase64Line(conn.(io.Writer), thisPublicKey)
	if err != nil {
		printErrorln(err.Error())
		return
	}

	printVerboseln("reading nonce...")
	nonce, err := readNonce(connReader)
	if err != nil {
		printErrorln(err.Error())
		return
	}
	printVerboseln("received nonce \"%x\"", nonce)

	printVerboseln("reading public key...")
	otherPublicKey, err := readPublicKey(connReader)
	if err != nil {
		printErrorln(err.Error())
		return
	}
	printVerboseln("received public key \"%x\"", thisPublicKey)

	printVerboseln("computing shared secret...")
	sharedSecret, err := computeSharedCurve25519Secret(otherPublicKey, privateKey)
	if err != nil {
		printErrorln(err.Error())
		return
	}
	printVerboseln("computed shared secret \"%x\"", sharedSecret)

	printInfoln("e2e key exchange complete")
}

func Send(message []byte, target string) error {
	printInfoln("connecting to %s...", target)
	conn, err := net.Dial("tcp", target)
	if err != nil {
		return err
	}
	defer conn.Close()
	defer printInfoln("connection closed")

	connReader := bufio.NewReader(conn)

	err = assertConnHello(connReader)
	if err != nil {
		return err
	}

	err = writeHello(conn.(io.Writer))
	if err != nil {
		return err
	}

	printVerboseln("generating transaction keys")
	privateKey, thisPublicKey, err := generateTransactionKeys()
	if err != nil {
		return err
	}
	nonce := GenerateNonce()

	printVerboseln("reading public key...")
	otherPublicKey, err := readPublicKey(connReader)
	if err != nil {
		return err
	}
	printVerboseln("received public key \"%x\"", otherPublicKey)

	printVerboseln("sending nonce \"%x\"", nonce)
	_, err = writeBase64Line(conn.(io.Writer), nonce)
	if err != nil {
		return err
	}

	printVerboseln("sending public key \"%x\"", thisPublicKey)
	_, err = writeBase64Line(conn.(io.Writer), thisPublicKey)
	if err != nil {
		return err
	}

	printVerboseln("computing shared secret...")
	sharedSecret, err := computeSharedCurve25519Secret(otherPublicKey, privateKey)
	if err != nil {
		return err
	}
	printVerboseln("computed shared secret \"%x\"", sharedSecret)

	printInfoln("e2e key exchange complete")

	return nil
}

func writeHello(conn io.Writer) error {
	_, err := conn.Write(bytes.Join([][]byte{[]byte("hello"), newlineByteArray}, []byte("")))
	if err != nil {
		return fmt.Errorf("error writing hello: %s, closing connection\n", err)
	}
	printVerboseln("successfully sent hello")
	return nil
}

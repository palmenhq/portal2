package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
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
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "no-trim-newline",
						Aliases: []string{"t"},
						Value:   false,
					},
				},
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() == 0 {
						return fmt.Errorf("no target address provided (expected i.e. \"127.0.0.1:1337\")")
					}

					if ctx.Args().Len() > 1 {
						return fmt.Errorf("too many arguments (expected flags before target address)")
					}

					targetAddress := ctx.Args().First()

					stdinStat, err := os.Stdin.Stat()
					if err != nil {
						return fmt.Errorf("error reading stdin")
					}
					if stdinStat.Size() == 0 {
						return fmt.Errorf("cannot send empty message")
					}
					messageBuf := bytes.NewBuffer([]byte{})
					_, err = messageBuf.ReadFrom(os.Stdin)
					if err != nil {
						return err
					}
					if ctx.Bool("no-trim-newline") {
						return Send(messageBuf.Bytes(), targetAddress)
					} else {
						return Send(bytes.TrimRight(messageBuf.Bytes(), "\n"), targetAddress)
					}
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

	err := writeHello(conn.(io.Writer))
	if err != nil {
		printErrorln(err.Error())
		return
	}

	err = assertConnHello(conn)
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
	if _, err := conn.Write(thisPublicKey); err != nil {
		printErrorln(err.Error())
		return
	}

	printVerboseln("reading nonce...")
	nonce, err := readNonce(conn)
	if err != nil {
		printErrorln(err.Error())
		return
	}
	printVerboseln("received nonce \"%x\"", nonce)

	printVerboseln("reading public key...")
	otherPublicKey, err := readPublicKey(conn)
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

	printInfoln("e2e encryption key exchange complete")

	encryptedMessageLengthRaw := make([]byte, 8)
	if _, err := conn.Read(encryptedMessageLengthRaw); err != nil {
		printErrorln("error reading message length: %s", err)
		return
	}
	encryptedMessageLength := binary.BigEndian.Uint32(encryptedMessageLengthRaw)
	encryptedMessage := make([]byte, encryptedMessageLength)
	if _, err := conn.Read(encryptedMessage); err != nil {
		printErrorln("error reading message: %s", err)
		return
	}

	decryptedMessage, err := AesGcmDecrypt(encryptedMessage, nonce, sharedSecret)
	if err != nil {
		printErrorln("error decrypting message: %s", err)
		_, _ = conn.Write([]byte("err"))
		return
	}

	fmt.Printf("decrypted message:\n-----\n%s\n-----\n", decryptedMessage)

	_, _ = conn.Write([]byte("oki"))
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
	if _, err := conn.Write(nonce); err != nil {
		return err
	}

	printVerboseln("sending public key \"%x\"", thisPublicKey)
	if _, err := conn.Write(thisPublicKey); err != nil {
		return err
	}

	printVerboseln("computing shared secret...")
	sharedSecret, err := computeSharedCurve25519Secret(otherPublicKey, privateKey)
	if err != nil {
		return err
	}
	printVerboseln("computed shared secret \"%x\"", sharedSecret)

	printInfoln("e2e encryption key exchange complete")

	printVerboseln("encrypting message")
	encryptedMessage, err := AesGcmEncrypt(message, nonce, sharedSecret)
	if err != nil {
		return err
	}
	printVerboseln("sending message")
	messageLength := int2UintByteArray(len(encryptedMessage))
	if _, err := conn.Write(messageLength); err != nil {
		return err
	}
	if _, err = conn.Write(encryptedMessage); err != nil {
		return err
	}
	printVerboseln("encrypted message (%d bytes, %d encrypted) sent", len(message), len(encryptedMessage))

	receipt := make([]byte, 3)
	if _, err := conn.Read(receipt); err != nil {
		return fmt.Errorf("error reading receipt, message delivery status unknown: %s", err)
	}

	if string(receipt) == "oki" {
		printInfoln("message successfully delivered and decrypted")
	} else if string(receipt) == "err" {
		printErrorln("recipient decryption error")
	}

	return nil
}

func writeHello(conn io.Writer) error {
	_, err := conn.Write([]byte("hello"))
	if err != nil {
		return fmt.Errorf("error writing hello: %s, closing connection\n", err)
	}
	printVerboseln("successfully sent hello")
	return nil
}

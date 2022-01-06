# portal2

Send messages p2p with end-to-end encryption.

## Disclaimer

This solution has not been tested enough to be considered secure, it's purely an experiment from my end. Do not use it for sensitive values, unless you know what you're doing.

## Setup

Use go to build it: `go build -v -o build/portal2`.

## Usage

Cd into `build`, or replace `./portal2` with `build/portal2`. Or just move the binary, whatever you feel like. Start the recipient server by running `./portal2 listen`. You should see the following

```
$ ./portal2 listen
accepting incoming connections on port 1337
```

You can then send a message by using `./portal2 send <target ip>:port`. It reads from stdin, so you can pass anything to it.

```
$ echo 'hello' | ./portal2 send 127.0.0.1:1337
connecting to 127.0.0.1:1337...
e2e encryption key exchange complete
message successfully delivered and decrypted
connection closed
```

On the recipient side you should now see

```
$ ./portal2 listen
accepting incoming connections on port 1337
---
accepted new connection from 127.0.0.1:60634
e2e encryption key exchange complete
decrypted message:
-----
hello
-----
connection closed
```

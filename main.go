package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/sha3"
)

func main() {
	flag.Parse()
	if flag.Arg(0) == "" {
		fmt.Println("[err] prefix must be provided")
		os.Exit(1)
	}

	onion := make(chan [2]string)
	keep := true

	fmt.Println("Generating..")
	for keep {
		go func() {
			address, priv := generateOnion()
			if strings.HasPrefix(address, flag.Arg(0)) {
				keep = false
				onion <- [2]string{address, priv}
			}
		}()
	}

	result := <-onion
	fmt.Printf("\nOnion Address: %s.onion\nPrivate Key: %s\n", result[0], result[1])
}

func generateOnion() (string, string) {
	var version byte = '\x03'
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	var sumBytes bytes.Buffer
	sumBytes.WriteString(".onion checksum")
	sumBytes.Write(pub)
	sumBytes.WriteByte(version)

	checksum := sha3.Sum256(sumBytes.Bytes())

	var addressBytes bytes.Buffer
	addressBytes.Write(pub)
	addressBytes.Write(checksum[:2])
	addressBytes.WriteByte(version)

	encodedAddress := base32.StdEncoding.EncodeToString(addressBytes.Bytes())
	encodedKEY := base32.StdEncoding.EncodeToString(priv.Seed())

	return strings.ToLower(encodedAddress), strings.ToLower(encodedKEY)
}

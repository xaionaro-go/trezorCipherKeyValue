package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"syscall"
	"encoding/hex"

	"github.com/conejoninja/tesoro/pb/messages"
	"github.com/pborman/getopt/v2"
	"github.com/xaionaro-go/trezor"
)

var (
	// Just some random values (from /dev/random)
	iv = []byte{
		0xf9, 0xa1, 0x99, 0xec, 0xa6, 0x81, 0x78, 0x19, 0xcc, 0x67, 0x55, 0x61, 0x6e, 0xc3, 0x1e, 0xd8,
	}
)

func usage() int {
	getopt.Usage()
	return int(syscall.EINVAL)
}

func checkError(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "Got error:", err)
	os.Exit(-1)
}

func main() {
	helpFlag := getopt.BoolLong("help", 'h', "print help message")
	encryptFlag := getopt.BoolLong("encrypt", 'e', "encrypt a key")
	decryptFlag := getopt.BoolLong("decrypt", 'd', "decrypt a key")
	hexFlag := getopt.BoolLong("hex", 'H', "consider encrypted key to be HEX-encoded (for both --encrypt and --decrypt)")
	verboseFlag := getopt.BoolLong("verbose", 'v', "print messages about what is going on")
	keyNameParameter := getopt.StringLong("key-name", 0, "unnamed key", "sets the name of a key to be encrypted/decrypted with the Trezor")
	getopt.Parse()

	if *helpFlag {
		os.Exit(usage())
	}

	if !*encryptFlag && !*decryptFlag {
		fmt.Fprintln(os.Stderr, "Error: Flag --encrypt or --decrypt is required.\n")
		os.Exit(usage())
	}

	trezorInstance := trezor.New()

	if *verboseFlag {
		fmt.Println("Reading the data from stdin.")
	}
	stdinBytes, err := ioutil.ReadAll(os.Stdin)
	checkError(err)
	data := stdinBytes

	if *decryptFlag {
		var dataHexed string
		if !*hexFlag {
			dataHexed = hex.EncodeToString(data)
		} else {
			dataHexed = string(data)
		}
		if len(dataHexed)%2 != 0 {
			panic(`len(dataHexed) is odd`)
		}
		for len(dataHexed)%32 != 0 {
			dataHexed += "00"
		}
		data = []byte(dataHexed)
	}

	
	if *verboseFlag {
		fmt.Println("Sent a request to a Trezor device (please confirm the operation if required).")
	}

	result, msgType := trezorInstance.CipherKeyValue(`m/71'/a6'/3'/45'/97'`, *encryptFlag, *keyNameParameter, data, iv, true, true)
	switch msgType {
	case messages.MessageType_MessageType_Success, messages.MessageType_MessageType_CipheredKeyValue:
	default:
		panic(fmt.Errorf("Unexpected message: %v: %v", msgType, string(result)))
	}

	if *encryptFlag && *hexFlag {
		result = []byte(hex.EncodeToString(result))
	}

	fmt.Print(string(result))
}


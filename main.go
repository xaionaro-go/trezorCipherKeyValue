package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"syscall"

	"github.com/conejoninja/tesoro/pb/messages"
	"github.com/pborman/getopt/v2"
	"github.com/xaionaro-go/cryptoWallet"
	"github.com/xaionaro-go/cryptoWallet/interfaces"
	"github.com/xaionaro-go/pinentry"
)

var (
	iv = []byte("trezorCipher IV")
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
	keyNameParameter := getopt.StringLong("key-name", 'k', "unnamed key", "sets the name of a key to be encrypted/decrypted with the Trezor")
	askpassPathParameter := getopt.StringLong("askpass-path", 'p', "/lib/cryptsetup/askpass", `sets the path of the utility to ask the PIN/Passphrase (for Trezor) [default: "/lib/cryptsetup/askpass"]`)
	usePinentryFlag := getopt.BoolLong("use-pinentry", 'P', `use "pinentry" utility to ask for PIN/Passphrase instead of "askpass"`)
	inputValueFileParameter := getopt.StringLong("input-value-file", 'i', "-", `sets the path of the file to read the input value [default: "-" (stdin)]; otherwise use can pass the input value using environment variable TREZOR_CIPHER_VALUE`)
	getopt.Parse()

	if *helpFlag {
		usage()
		os.Exit(0)
	}

	if !*encryptFlag && !*decryptFlag {
		fmt.Fprintln(os.Stderr, "Error: Flag --encrypt or --decrypt is required.\n")
		os.Exit(usage())
	}

	wallet := cryptoWallet.FindAny()
	if wallet == nil {
		panic("No trezor devices found")
	}
	trezorInstance, ok := wallet.(cryptoWalletInterfaces.Trezor)
	if !ok {
		panic("No trezor devices found")
	}

	if *usePinentryFlag {
		p, _ := pinentry.NewPinentryClient()
		defer p.Close()
		trezorInstance.SetGetPinFunc(func(title, description, ok, cancel string) ([]byte, error) {
			p.SetTitle(title)
			p.SetDesc(description)
			p.SetPrompt(title)
			p.SetOK(ok)
			p.SetCancel(cancel)
			return p.GetPin()
		})
	} else {
		trezorInstance.SetGetPinFunc(func(title, description, ok, cancel string) ([]byte, error) {
			if *verboseFlag {
				fmt.Printf(`Running command "%v %v"`+"\n", *askpassPathParameter, title)
			}
			cmd := exec.Command(*askpassPathParameter, title)
			cmd.Stdin = os.Stdin
			cmd.Stderr = os.Stderr
			return cmd.Output()
		})
	}
	trezorInstance.SetGetConfirmFunc(func(title, description, ok, cancel string) (bool, error) {
		return false, nil // Confirmation is required to reconnect to Trezor. We considered that disconnected Trezor is enough to exit the program.
	})

	if *verboseFlag {
		fmt.Println("Setting Trezor device state to the initial state.")
	}
	err := trezorInstance.Reset()
	if err != nil {
		panic(fmt.Errorf("Cannot set the Trezor device state to the initial state"))
	}

	data := []byte(os.Getenv("TREZOR_CIPHER_VALUE"))
	if len(data) == 0 { // If the variable wasn't set then reading from stdin/file (see option `--input-value-file`)
		if *inputValueFileParameter == "-" {
			if *verboseFlag {
				fmt.Println("Reading the data from stdin.")
			}
			var err error
			data, err = ioutil.ReadAll(os.Stdin)
			checkError(err)
		} else {
			if *verboseFlag {
				fmt.Printf(`Reading the data file "%v"`+"\n", *inputValueFileParameter)
			}
			var err error
			data, err = ioutil.ReadFile(*inputValueFileParameter)
			checkError(err)
		}
	}

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

	result, msgType := trezorInstance.CipherKeyValue(`m/10019'/1'`, *encryptFlag, *keyNameParameter, data, iv, true, true)
	switch messages.MessageType(msgType) {
	case messages.MessageType_MessageType_Success, messages.MessageType_MessageType_CipheredKeyValue:
	default:
		panic(fmt.Errorf("Unexpected message: %v: %v", msgType, string(result)))
	}

	if *encryptFlag && *hexFlag {
		result = []byte(hex.EncodeToString(result))
	}

	fmt.Print(string(result))
}

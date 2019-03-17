/*
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"

	"github.com/jesseduffield/pty"
	"github.com/pborman/getopt/v2"
	"github.com/xaionaro-go/cryptoWallet"
	"github.com/xaionaro-go/cryptoWallet/interfaces"
	"github.com/xaionaro-go/pinentry"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	cryptsetupAskpassPath = `/lib/cryptsetup/askpass`
	systemdAskpassPath    = `systemd-ask-password`
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

func checkIfExecutableExists(name string) bool {
	if len(name) == 0 {
		return false
	}
	if name[0] == '/' {
		_, err := os.Stat(name)
		return err == nil
	}

	for _, dir := range strings.Split(os.Getenv(`PATH`), `:`) {
		if _, err := os.Stat(path.Join(dir, name)); err == nil {
			return true
		}
	}

	return false
}

func main() {
	helpFlag := getopt.BoolLong("help", 'h', "print help message")
	encryptFlag := getopt.BoolLong("encrypt", 'e', "encrypt a key")
	decryptFlag := getopt.BoolLong("decrypt", 'd', "decrypt a key")
	dummyDeviceFlag := getopt.BoolLong("dummy", 'D', "imitate a dummy Trezor device")
	hexFlag := getopt.BoolLong("hex", 'H', "consider encrypted key to be HEX-encoded (for both --encrypt and --decrypt)")
	verboseFlag := getopt.BoolLong("verbose", 'v', "print messages about what is going on")
	keyNameParameter := getopt.StringLong("key-name", 'k', "unnamed key", "sets the name of a key to be encrypted/decrypted with the Trezor")
	askpassPathParameter := getopt.StringLong("askpass-path", 'p', "", `sets the path of the utility to ask the PIN/Passphrase (for Trezor) [default: "`+cryptsetupAskpassPath+`", "`+systemdAskpassPath+`"]`)
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
	if *askpassPathParameter == "" {
		switch {
		case checkIfExecutableExists(cryptsetupAskpassPath):
			*askpassPathParameter = cryptsetupAskpassPath
		case checkIfExecutableExists(systemdAskpassPath):
			*askpassPathParameter = systemdAskpassPath
		default:
			fmt.Fprintln(os.Stderr, `Error: There's no askpass utility found. Please use option -P or -p to select an utility to enter a PIN-code and a passphrase.`)
			os.Exit(6)
		}
	}

	data := []byte(os.Getenv("TREZOR_CIPHER_VALUE"))
	if len(data) == 0 { // If the variable wasn't set then reading from stdin/file (see option `--input-value-file`)
		if *inputValueFileParameter == "-" {
			if *verboseFlag {
				fmt.Fprintln(os.Stderr, "Reading the data from stdin.")
			}
			var err error
			data, err = ioutil.ReadAll(os.Stdin)
			checkError(err)
		} else {
			if *verboseFlag {
				fmt.Fprintf(os.Stderr, `Reading the data file "%v"`+"\n", *inputValueFileParameter)
			}
			var err error
			data, err = ioutil.ReadFile(*inputValueFileParameter)
			checkError(err)
		}
	}

	var wallet cryptoWalletInterfaces.Wallet
	if *dummyDeviceFlag {
		wallet = cryptoWallet.NewDummy()
	} else {
		wallet = cryptoWallet.FindAny()
	}
	if wallet == nil {
		fmt.Fprintf(os.Stderr, "No trezor devices found\n")
		os.Exit(1)
	}
	if !*dummyDeviceFlag {
		if trezorInstance, ok := wallet.(cryptoWalletInterfaces.Trezor); ok {
			trezorInstance.SetDefaultAskOnEncode(true)
		} else {
			fmt.Fprintf(os.Stderr, "No trezor devices found\n")
			os.Exit(1)
		}
	}

	if *usePinentryFlag {
		p, _ := pinentry.NewPinentryClient()
		defer p.Close()
		wallet.SetGetPinFunc(func(title, description, ok, cancel string) ([]byte, error) {
			p.SetTitle(title)
			p.SetDesc(description)
			p.SetPrompt(title)
			p.SetOK(ok)
			p.SetCancel(cancel)
			return p.GetPin()
		})
	} else {
		wallet.SetGetPinFunc(func(title, description, ok, cancel string) ([]byte, error) {
			var result bytes.Buffer
			if *verboseFlag {
				fmt.Fprintf(os.Stderr, `Running command "%v %v"`+"\n", *askpassPathParameter, title)
			}
			cmd := exec.Command(*askpassPathParameter, title)
			cmd.Stdout = &result
			ptmx, err := pty.Start(cmd)
			if err != nil {
				return nil, err
			}
			defer func() { _ = ptmx.Close() }()

			oldStdinState, err := terminal.MakeRaw(int(os.Stdin.Fd()))
			if err == nil {
				defer func() { _ = terminal.Restore(int(os.Stdin.Fd()), oldStdinState) }()
			} else {
				fmt.Fprintf(os.Stderr, `The stdin is already closed, but we're waiting for reply from an askpass utility (this is OK, if the utility is not waiting any input from out stdin).`)
			}

			go io.Copy(ptmx, os.Stdin)
			io.Copy(os.Stderr, ptmx)
			r := strings.Trim(result.String(), "\n\r")
			return []byte(r), nil
		})
	}
	wallet.SetGetConfirmFunc(func(title, description, ok, cancel string) (bool, error) {
		return false, nil // Confirmation is required to reconnect to Trezor. We considered that disconnected Trezor is enough to exit the program.
	})

	if *verboseFlag {
		fmt.Fprintln(os.Stderr, "Setting Trezor device state to the initial state.")
	}
	err := wallet.Reset()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot set the Trezor device state to the initial state\n")
		os.Exit(2)
	}

	if *decryptFlag {
		var dataHexed string
		if !*hexFlag {
			dataHexed = hex.EncodeToString(data)
		} else {
			dataHexed = string(data)
		}
		if len(dataHexed)%2 != 0 {
			panic(`internal error: len(dataHexed) is odd`)
		}
		for len(dataHexed)%32 != 0 {
			dataHexed += "00"
		}
		data = []byte(dataHexed)
	}

	if *verboseFlag {
		fmt.Fprintln(os.Stderr, "Sent a request to a Trezor device (please confirm the operation if required).")
	}

	var result []byte
	if *encryptFlag {
		result, err = wallet.EncryptKey(`m/10019'/1'`, data, iv, *keyNameParameter)
	} else {
		result, err = wallet.DecryptKey(`m/10019'/1'`, data, iv, *keyNameParameter)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err)
		os.Exit(3)
	}

	if *encryptFlag && *hexFlag {
		result = []byte(hex.EncodeToString(result))
	}

	fmt.Print(string(result))
}

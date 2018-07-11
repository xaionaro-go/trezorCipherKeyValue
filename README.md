A pipeline utility to encrypt/decrypt values using a [Trezor One](https://github.com/trezor/trezor-mcu) device.

Quick start:
```sh
GOPATH="`go env GOPATH`"

go get github.com/xaionaro-go/trezorCipherKeyValue
go install github.com/xaionaro-go/trezorCipherKeyValue
$ ENCRYPTED_KEY="$(TREZOR_CIPHER_VALUE="test data" "$GOPATH"/bin/trezorCipherKeyValue --encrypt --hex)"
PIN ****
Passphrase ********
$ echo $ENCRYPTED_KEY
304bc949dd6a39049e3c40ea48ae75e6
$ echo -n "$ENCRYPTED_KEY" | "$GOPATH"/bin/trezorCipherKeyValue --decrypt --hex
Passphrase ********
Some key
```

Another example:
```sh
$ ENCRYPTED_KEY="`TREZOR_CIPHER_VALUE="someKeyHere" "$GOPATH"/bin/trezorCipherKeyValue --key-name myKey --use-pinentry --encrypt`"
$ echo -n "$ENCRYPTED_KEY" | hexdump -C
00000000  66 c7 a5 bb 0d fd 5d a7  e5 df c9 74 36 1a 5d 8d  |f.....]....t6.].|
00000010
$ echo -n "$ENCRYPTED_KEY" | "$GOPATH"/bin/trezorCipherKeyValue --key-name myKey --use-pinentry --decrypt | hexdump -C
00000000  73 6f 6d 65 4b 65 79 48  65 72 65 0a 00 00 00 00  |someKeyHere.....|
00000010
```

An encrypted value is aligned to 16 bytes.

Arguments:
```
$ "$GOPATH"/bin/trezorCipherKeyValue --help
Usage: trezorCipherKeyValue [-dehHPv] [-i value] [-k value] [-p value] [parameters ...]
 -d, --decrypt  decrypt a key
 -e, --encrypt  encrypt a key
 -h, --help     print help message
 -H, --hex      consider encrypted key to be HEX-encoded (for both --encrypt
                and --decrypt)
 -i, --input-value-file=value
                sets the path of the file to read the input value [default:
                "-" (stdin)]; otherwise use can pass the input value using
                environment variable TREZOR_CIPHER_KV
 -k, --key-name=value
                sets the name of a key to be encrypted/decrypted with the
                Trezor
 -p, --askpass-path=value
                sets the path of the utility to ask the PIN/Passphrase (for
                Trezor) [default: "/lib/cryptsetup/askpass"]
 -P, --use-pinentry
                use "pinentry" utility to ask for PIN/Passphrase instead of
                "askpass"
 -v, --verbose  print messages about what is going on
```

```
```

The utility was requested here: [https://github.com/xaionaro-go/trezorLuks/issues/2](https://github.com/xaionaro-go/trezorLuks/issues/2)

Documentation:
* [SLIP-0011 : Symmetric encryption of key-value pairs using deterministic hierarchy](https://github.com/satoshilabs/slips/blob/master/slip-0011.md)

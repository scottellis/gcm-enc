package main

import (
    "flag"
    "fmt"
    "github.com/gtank/cryptopasta"
    "io/ioutil"
    "os"
)

const AES_KEY_SIZE = 32
const IV_SIZE = 12
const GCM_TAG_SIZE = 16
const AES_PAD_SIZE = 16


func usage() {
    fmt.Println("\n  Usage: gcm-enc -k <key-file> -p <plaintext-file> [-c <ciphertext-file>][-v]")
    os.Exit(1)
}

func dump_hex(prompt string, hex []byte) {
    fmt.Printf(prompt);

    for i := 0; i < len(hex); i++ {
        if ((i % 16) == 0) {
            fmt.Println("")
        }

        fmt.Printf("%02x ", hex[i])
    }

    fmt.Println("\n")
}

func readKey(path string) *[32]byte {
    key := [32]byte{}

    _, err := os.Stat(path)

    if err == nil {
        data, err := ioutil.ReadFile(path)

        if err != nil {
            panic(err)
        }

        if len(data) != AES_KEY_SIZE {
            msg := fmt.Sprintf("Unsupported key size: %d\n", len(data))
            panic(msg)
        }

        copy(key[:], data[:32])

    } else if os.IsNotExist(err) {
        temp := cryptopasta.NewEncryptionKey()

        copy(key[:], temp[:])

        err := ioutil.WriteFile(path, key[:], 0640)

        if err != nil {
            panic(err)
        }
    } else {
        panic(err);
    }

    return &key;
}

func readPlaintextPadded(path string) *[]byte {
    text, err := ioutil.ReadFile(path)

    if err != nil {
        panic(err)
        os.Exit(1)
    }

    len := len(text)

    if len == 0 {
        fmt.Println("Plaintext file %s is empty", path)
        os.Exit(1)
    }

    var padchar byte = (byte)(len / AES_PAD_SIZE)

    if padchar == 0x00 {
        padchar = 0x10
    }

    plaintext := make([]byte, len + int(padchar))

    copy(plaintext[:len], text[:])

    for i := 0; i < int(padchar); i++ {
        plaintext[len] = padchar
        len++
    }

    return &plaintext
}

func main() {

    key_file := flag.String("k", "", "key file")
    plaintext_file := flag.String("p", "", "input plaintext file")
    ciphertext_file := flag.String("c", "", "output ciphertext file")
    verbose := flag.Bool("v", false, "verbose mode")

    flag.Parse()

    if len(*key_file) == 0 {
        fmt.Println("A key file is required")
        usage()
    }

    if len(*plaintext_file) == 0 {
        fmt.Println("A plaintext file is required")
        usage();
    }

    key := readKey(*key_file)

    plaintext := readPlaintextPadded(*plaintext_file)

    if *verbose {
        dump_hex("key: ", key[:])
        dump_hex("plaintext: ", *plaintext)
    }

    ciphertext, err := cryptopasta.Encrypt(*plaintext, key)

    if err != nil {
        panic(err)
    }

    if *verbose {
        dump_hex("iv: ", ciphertext[:IV_SIZE])
        dump_hex("ciphertext: ", ciphertext[12:len(ciphertext) - GCM_TAG_SIZE])
        dump_hex("tag: ", ciphertext[len(ciphertext) - GCM_TAG_SIZE:])
    }

    if len(*ciphertext_file) != 0 {
        err = ioutil.WriteFile(*ciphertext_file, ciphertext, 0644)

        if err != nil {
            panic(err)
        }
    }
}

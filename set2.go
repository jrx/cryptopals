package cryptopals

import (
	"bytes"
	"log"
)

// PadPKCS7 pads a byte slice with PKCS#7 padding.
func PadPKCS7(in []byte, size int) []byte {
	if size == len(in) {
		return in
	}
	if size < len(in) {
		log.Fatal("size must be greater than input length")
	}
	if size >= 256 {
		log.Fatal("size must be less than 256")
	}
	padLen := size - len(in)%size
	return append(in, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
}

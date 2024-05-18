package cryptopals

import (
	"bytes"
	"crypto/cipher"
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

// EncryptCBC encrypts a byte slice using AES in CBC mode.
func EncryptCBC(b cipher.Block, iv, in []byte) []byte {
	size := b.BlockSize()
	if len(in)%size != 0 {
		log.Fatal("input length must be a multiple of the block size")
	}
	if len(iv) != size {
		log.Fatal("iv length must be equal to the block size")
	}
	out := make([]byte, len(in))
	prev := iv

	for i := 0; i < len(in)/size; i++ {
		copy(out[i*size:], XOR(in[i*size:(i+1)*size], prev))
		b.Encrypt(out[i*size:], out[i*size:])
		prev = out[i*size : (i+1)*size]
	}

	return out
}

// DecryptCBC decrypts a byte slice using AES in CBC mode.
func DecryptCBC(b cipher.Block, iv, in []byte) []byte {
	size := b.BlockSize()
	if len(in)%size != 0 {
		log.Fatal("input length must be a multiple of the block size")
	}
	if len(iv) != size {
		log.Fatal("iv length must be equal to the block size")
	}
	out := make([]byte, len(in))
	prev := iv
	buf := make([]byte, size)
	for i := 0; i < len(in)/size; i++ {
		b.Decrypt(buf, in[i*size:])
		copy(out[i*size:], XOR(buf, prev))
		prev = in[i*size : (i+1)*size]
	}

	return out
}

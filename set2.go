package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
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

// EncryptECB encrypts a byte slice using AES in ECB mode.
func EncryptECB(b cipher.Block, in []byte) []byte {
	size := b.BlockSize()
	if len(in)%size != 0 {
		log.Fatal("input length must be a multiple of the block size")
	}
	out := make([]byte, len(in))
	for i := 0; i < len(in); i += size {
		b.Encrypt(out[i:], in[i:])
	}
	return out
}

func NewECBCBCOracle() func([]byte) []byte {
	key := make([]byte, 16)
	rand.Read(key)
	cipher, _ := aes.NewCipher(key)

	return func(in []byte) []byte {

		prefixRNG, _ := rand.Int(rand.Reader, big.NewInt(5))
		prefix := make([]byte, 5+prefixRNG.Int64())
		rand.Read(prefix)

		suffixRNG, _ := rand.Int(rand.Reader, big.NewInt(5))
		suffix := make([]byte, 5+suffixRNG.Int64())
		rand.Read(suffix)

		in = append(append(prefix, in...), suffix...)
		in = PadPKCS7(in, len(in)+16-len(in)%16)

		r, _ := rand.Int(rand.Reader, big.NewInt(2))
		if r.Int64() == 0 {
			iv := make([]byte, 16)
			rand.Read(iv)
			return EncryptCBC(cipher, iv, in)
		} else {
			return EncryptECB(cipher, in)
		}
	}
}

func NewECBSuffixOracle(secret []byte) func([]byte) []byte {
	key := make([]byte, 16)
	rand.Read(key)
	cipher, _ := aes.NewCipher(key)

	return func(in []byte) []byte {
		// time.Sleep(200 * time.Microsecond)
		in = append(in, secret...)
		in = PadPKCS7(in, len(in)+16-len(in)%16)
		return EncryptECB(cipher, in)
	}
}

func RecoverECBSuffix(oracle func([]byte) []byte) []byte {
	bs := 0
	for blockSize := 16; blockSize <= 512; blockSize += 16 {
		msg := bytes.Repeat([]byte{42}, blockSize*2)
		msg = append(msg, 3)
		cipher, err := aes.NewCipher(make([]byte, blockSize))
		if err != nil {
			log.Fatal(err)
		}
		if DetectECB(oracle(msg)[:blockSize*2], cipher) {
			bs = blockSize
			break
		}
	}
	if bs == 0 {
		log.Fatal("could not determine block size")
	}
	log.Printf("Block size is likely: %d", bs)

	buildDict := func(known []byte) map[string]byte {
		dict := make(map[string]byte)

		msg := bytes.Repeat([]byte{42}, bs)
		msg = append(msg, known...)
		msg = append(msg, '?')
		msg = msg[len(msg)-bs:]

		for b := 0; b < 256; b++ {
			msg[bs-1] = byte(b)
			res := string(oracle(msg)[:bs])
			dict[res] = byte(b)
		}
		return dict
	}
	dict := buildDict(nil)
	msg := bytes.Repeat([]byte{42}, bs-1)
	res := string(oracle(msg)[:bs])
	firstByte := dict[res]

	log.Printf("First byte is likely: %c / %v", firstByte, firstByte)

	var plaintext []byte
	for i := 0; i < len(oracle([]byte{})); i++ {
		dict := buildDict(plaintext)
		msg := bytes.Repeat([]byte{42}, Mod(bs-i-1, bs))
		skip := i / bs * bs
		res := string(oracle(msg)[skip : skip+bs])
		plaintext = append(plaintext, dict[res])

		fmt.Printf("%c", dict[res])

	}
	fmt.Println()
	return nil
}

func Mod(a, b int) int {
	return (a%b + b) % b
}

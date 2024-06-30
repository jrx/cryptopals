package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func NewCBCPaddingOracles(plaintext []byte) (
	generateMessage func() []byte,
	checkMessagePadding func(message []byte) bool,
) {
	key := make([]byte, 16)
	rand.Read(key)
	cipher, _ := aes.NewCipher(key)
	generateMessage = func() []byte {
		msg := plaintext
		msg = PadPKCS7(msg, 16)

		// log.Printf("padded: %q", msg[len(msg)-4])

		iv := make([]byte, 16)
		rand.Read(iv)

		ct := EncryptCBC(cipher, iv, msg)
		return append(iv, ct...)
	}
	checkMessagePadding = func(message []byte) bool {
		iv := message[:16]
		msg := message[16:]
		res := UnpadPKCS7(DecryptCBC(cipher, iv, msg))
		return res != nil
	}
	return
}

func AttackCBCPaddingOracle(
	ct []byte,
	checkMessagePadding func(ct []byte) bool) []byte {

	findNextByte := func(known, iv, block []byte) []byte {
		if len(block) != 16 || len(iv) != 16 || len(known) >= 16 {
			panic("wrong lengths for findNextByte")
		}
		payload := make([]byte, 32)
		copy(payload, iv)
		copy(payload[16:], block)
		plaintext := append([]byte{0}, known...)
		for p := 0; p < 256; p++ {
			copy(payload, iv)
			plaintext[0] = byte(p)

			for i := range plaintext {
				payload[len(payload)-1-16-i] ^= plaintext[len(plaintext)-1-i]
			}

			// apply valid padding
			for i := range plaintext {
				payload[len(payload)-1-16-i] ^= byte(len(plaintext))
			}
			// check we actually changed something
			if bytes.Equal(payload[:16], iv) {
				continue
			}
			if checkMessagePadding(payload) {
				return plaintext
			}
		}
		// if the only one that works is not changing anything,
		// there's already a padding of len(plaintext)
		plaintext[0] = byte(len(plaintext))
		for _, c := range plaintext {
			if c != byte(len(plaintext)) {
				plaintext[1] ^= byte(len(plaintext))
				// correct and retry
				return plaintext[1:]
			}
		}
		return plaintext

	}

	if len(ct)%16 != 0 {
		panic("AttackCBCPaddingOracle: invalid ciphertext length")
	}

	var plaintext []byte
	for b := 0; b < len(ct)/16-1; b++ {
		var known []byte
		blockStart := len(ct) - b*16 - 16
		block := ct[blockStart : blockStart+16]
		iv := ct[blockStart-16 : blockStart]
		for len(known) < 16 {
			known = findNextByte(known, iv, block)
			// log.Printf("-> %q", known)
			// time.Sleep(1 * time.Second)
		}

		plaintext = append(known, plaintext...)
	}
	return UnpadPKCS7(plaintext)
}

// EncryptCTR encrypts a byte slice using AES in CTR (Counter) mode.
func EncryptCTR(src []byte, b cipher.Block, nonce []byte) []byte {
	input, output := make([]byte, b.BlockSize()), make([]byte, b.BlockSize())
	copy(input, nonce)
	var dst []byte
	for i := 0; i < len(src); i += b.BlockSize() {
		b.Encrypt(output, input)
		cipherText := XOR(output, src[i:])
		dst = append(dst, cipherText...)

		j := len(nonce)
		for {
			input[j] += 1
			if input[j] != 0 {
				break
			}
			j++
		}
	}
	return dst
}

var decryptCTR = EncryptCTR

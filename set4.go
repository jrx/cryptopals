package cryptopals

import (
	"crypto/aes"
	"crypto/rand"
)

func NewCTREditOracles(plaintext []byte) (
	ciphertext []byte,
	edit func(ciphertext []byte, offset int, newText []byte) []byte,
) {
	key := make([]byte, 16)
	rand.Read(key)
	cipher, _ := aes.NewCipher(key)

	iv := make([]byte, 8)
	rand.Read(iv)

	ct := EncryptCTR(plaintext, cipher, iv)
	ciphertext = append(iv, ct...)

	edit = func(ciphertext []byte, offset int, newText []byte) []byte {
		iv := ciphertext[:8]
		msg := ciphertext[8:]
		plaintext := DecryptCTR(msg, cipher, iv)

		copy(plaintext[offset:], newText)

		ct := EncryptCTR(plaintext, cipher, iv)
		var res []byte
		res = append(res, iv...)
		res = append(res, ct...)
		return res
	}
	return
}

func AttackCTREditOracle(ciphertext []byte,
	edit func(ciphertext []byte, offset int, newText []byte) []byte) []byte {
	var plaintext []byte
	for offset := 8; offset < len(ciphertext); offset += 20 {
		newCT := edit(ciphertext, offset-8, make([]byte, 20))
		p := XOR(newCT[offset:offset+20], ciphertext[offset:offset+20])
		plaintext = append(plaintext, p...)
	}
	return plaintext
}

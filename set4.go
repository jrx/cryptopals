package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"log"
	"regexp"
	"strings"
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

func NewCTRCookieOracles() (
	generateCookie func(email string) string,
	amIAdmin func(string) bool,
) {
	key := make([]byte, 16)
	rand.Read(key)
	cipher, _ := aes.NewCipher(key)

	generateCookie = func(email string) string {

		profile := []byte("comment1=cooking%20MCs;userdata=")
		qEmail := bytes.Replace([]byte(email), []byte("="), []byte("%3D"), -1)
		qEmail = bytes.Replace(qEmail, []byte(";"), []byte("%3B"), -1)
		profile = append(profile, qEmail...)
		profile = append(profile, ";comment2=%20like%20a%20pound%20of%20bacon"...)

		iv := make([]byte, 8)
		rand.Read(iv)
		cookie := EncryptCTR(profile, cipher, iv)
		return string(iv) + string(cookie)
	}

	amIAdmin = func(cookie string) bool {
		iv := []byte(cookie[:8])
		msg := []byte(cookie[8:])
		cookie = string(DecryptCTR(msg, cipher, iv))
		log.Printf("%q", cookie)
		return strings.Contains(cookie, ";admin=true")
	}
	return
}

func MakeCTRAdminCookie(generateCookie func(email string) string) string {
	prefix := "comment1=cooking%20MCs;userdata="
	target := "AA;admin=true;AA"
	p := strings.Repeat("*", 16)
	out := generateCookie(p)
	out1 := out[:8+len(prefix)]
	out2 := out[8+len(prefix) : 8+len(prefix)+16]
	out3 := out[8+len(prefix)+16:]
	out2 = XORString(out2, XORString(strings.Repeat("*", 16), target))
	return out1 + out2 + out3
}

func NewCBCKeyEqIVOracles() (
	encryptMessage func([]byte) []byte,
	decryptMessage func([]byte) error,
	isKeyCorrect func([]byte) bool, // for testing
) {
	key := make([]byte, 16)
	rand.Read(key)
	cipher, _ := aes.NewCipher(key)

	encryptMessage = func(message []byte) []byte {
		return EncryptCBC(cipher, key, PadPKCS7(message, 16))
	}

	decryptMessage = func(ciphertext []byte) error {
		plaintext := UnpadPKCS7(DecryptCBC(cipher, key, ciphertext))
		// Matches all printable characters
		if !regexp.MustCompile(`^[ -~]+$`).Match(plaintext) {
			return fmt.Errorf("invalid message: %s", plaintext)
		}
		return nil
	}

	isKeyCorrect = func(k []byte) bool {
		return bytes.Equal(k, key)
	}

	return
}

func RecoverCBCKeyEqIV(
	encryptMessage func([]byte) []byte,
	decryptMessage func([]byte) error,
) []byte {
	ciphertext := encryptMessage(bytes.Repeat([]byte("A"), 16*4))
	copy(ciphertext[16:], make([]byte, 16))
	copy(ciphertext[32:], ciphertext[:16])
	err := decryptMessage(ciphertext).Error()
	plaintext := []byte(strings.TrimPrefix(err, "invalid message: "))
	if len(plaintext) != 16*4 {
		println(len(plaintext))
		panic("unexpected plaintext length")
	}
	return XOR(plaintext[:16], plaintext[32:48])
}

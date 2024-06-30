package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"testing"
)

func decodeBase64(t *testing.T, b64Text string) []byte {
	text, err := base64.StdEncoding.DecodeString(b64Text)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	return text
}

func TestNewCBCPaddingOracles(t *testing.T) {

	plaintexts := [][]byte{
		decodeBase64(t, "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="),
		decodeBase64(t, "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="),
		decodeBase64(t, "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="),
		decodeBase64(t, "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="),
		decodeBase64(t, "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"),
		decodeBase64(t, "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="),
		decodeBase64(t, "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="),
		decodeBase64(t, "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="),
		decodeBase64(t, "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="),
		decodeBase64(t, "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"),
	}

	for _, plaintext := range plaintexts {
		encryptMessage, checkMessagePadding := NewCBCPaddingOracles(plaintext)

		res := AttackCBCPaddingOracle(encryptMessage(), checkMessagePadding)
		t.Logf("-> %q", res)

		if !bytes.Equal(res, plaintext) {
			t.Errorf("Plaintext %q recovered incorrectly from %q", res, plaintext)
		}
	}

}

func TestEncryptCTR(t *testing.T) {
	b64Text := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	nonce := make([]byte, 8)
	key := []byte("YELLOW SUBMARINE")
	cipher, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf("Error: %s", err)
	}

	msg := decodeBase64(t, b64Text)
	res := decryptCTR(msg, cipher, nonce)
	t.Logf("%q", res)
	if len(res) != len(msg) {
		t.Error("Wrong length.")
	}
}

package cryptopals

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestBreakSingleByteXOR(t *testing.T) {
	expected := "Now that the party is jumping\n"
	res, err := BreakSingleByteXOR("testdata/4.txt")
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	if res != expected {
		t.Errorf("Expected %s, got %s", expected, res)
	}
}

func TestBreakRepeatingKeyXOR(t *testing.T) {
	expected := "I'm back and I'm ringin' the bell \nA rockin' on the mike while"
	res, err := BreakRepeatingKeyXOR("testdata/6.txt")
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	if !strings.HasPrefix(res, expected) {
		t.Errorf("Expected %s, got %s", expected, res)
	}
}

func TestDecryptECB(t *testing.T) {

	b64text, err := os.ReadFile("testdata/7.txt")
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	text, err := base64.StdEncoding.DecodeString(string(b64text))
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	cipher, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Errorf("Error: %s", err)
	}

	expected := "I'm back and I'm ringin' the bell \nA rockin' on the mike while"
	res := DecryptECB(text, cipher)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	if !strings.HasPrefix(string(res), expected) {
		t.Errorf("Expected %s, got %s", expected, res)
	}
}

func TestDetectECB(t *testing.T) {
	lines, err := ReadLines("testdata/8.txt")
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	cipher, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	for i, line := range lines {
		res, err := hex.DecodeString(line)
		if err != nil {
			t.Errorf("Error: %s", err)
		}
		if DetectECB(res, cipher) {
			t.Logf("Ciphertext %d is encrypted with ECB", i+1)
		}
	}
}

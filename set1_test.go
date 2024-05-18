package cryptopals

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestHexToBase64(t *testing.T) {
	base64String := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	res, err := HexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	if res != base64String {
		t.Errorf("Expected %s, got %s", base64String, res)
	}
}

func TestFixedXOR(t *testing.T) {
	expected := "746865206b696420646f6e277420706c6179"
	res, err := FixedXOR("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	if res != expected {
		t.Errorf("Expected %s, got %s", expected, res)
	}
}

func TestSingleByteXOR(t *testing.T) {
	expected := "Cooking MC's like a pound of bacon"
	res, _, _, err := SingleByteXOR("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	if res != expected {
		t.Errorf("Expected %s, got %s", expected, res)
	}
}

func TestRepeatingKeyXOR(t *testing.T) {
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	res, err := RepeatingKeyXOR("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE")
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	if res != expected {
		t.Errorf("Expected %s, got %s", expected, res)
	}
}

func TestHammingDistance(t *testing.T) {
	expected := 37
	res, err := HammingDistance("this is a test", "wokka wokka!!!")
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	if res != expected {
		t.Errorf("Expected %d, got %d", expected, res)
	}
}

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

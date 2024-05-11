package cryptopals

import (
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
	res, _, err := SingleByteXOR("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	if res != expected {
		t.Errorf("Expected %s, got %s", expected, res)
	}
}

func TestDetectSingleByteXOR(t *testing.T) {
	expected := "Now that the party is jumping\n"
	res, err := DetectSingleByteXOR("data/4.txt")
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	if res != expected {
		t.Errorf("Expected %s, got %s", expected, res)
	}
}

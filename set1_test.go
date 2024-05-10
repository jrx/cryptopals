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

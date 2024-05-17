package cryptopals

import (
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

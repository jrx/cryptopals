package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"os"
	"testing"
)

func TestPadPKCS7(t *testing.T) {
	tests := []struct {
		in   []byte
		size int
		want []byte
	}{
		{[]byte("YELLOW SUBMARINE"), 20, []byte("YELLOW SUBMARINE\x04\x04\x04\x04")},
		{[]byte("YELLOW SUBMARINE"), 16, []byte("YELLOW SUBMARINE")},
	}

	for _, test := range tests {
		got := PadPKCS7(test.in, test.size)
		if !bytes.Equal(got, test.want) {
			t.Errorf("PadPKCS7(%q, %d) = %q, want %q", test.in, test.size, got, test.want)
		}
	}
}

func TestEncryptCBC(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	text := []byte("YELLOW SUBMARINEYELLOW SUBMARINE")
	cipher, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf("Error: %s", err)
	}

	got := DecryptCBC(cipher, iv, EncryptCBC(cipher, iv, text))
	if !bytes.Equal(got, text) {
		t.Errorf("EncryptCBC(DecryptCBC(%q)) = %q, want %q", text, got, text)
	}

	b64text, err := os.ReadFile("testdata/10.txt")
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	text, err = base64.StdEncoding.DecodeString(string(b64text))
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	t.Logf("%s", DecryptCBC(cipher, iv, text))
}

func TestEncryptECB(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	text := []byte("YELLOW SUBMARINEYELLOW SUBMARINE")
	cipher, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf("Error: %s", err)
	}

	got := DecryptECB(EncryptECB(cipher, text), cipher)
	if !bytes.Equal(got, text) {
		t.Errorf("EncryptECB(DecryptECB(%q)) = %q, want %q", text, got, text)
	}
}

func TestNewECBCBCOracle(t *testing.T) {
	oracle := NewECBCBCOracle()
	key := []byte("YELLOW SUBMARINE")
	text := []byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE")
	cipher, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	cbc, ecb := 0, 0
	for i := 0; i < 500; i++ {
		if DetectECB(oracle(text), cipher) {
			ecb++
		} else {
			cbc++
		}
	}
	t.Logf("ECB: %d, CBC: %d", ecb, cbc)
}

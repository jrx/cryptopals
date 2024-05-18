package cryptopals

import (
	"bytes"
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

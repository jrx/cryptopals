package cryptopals

import (
	"crypto/aes"
	"testing"
)

func TestBreakAESCTR(t *testing.T) {

	cipher, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Errorf("Error: %s", err)
	}

	b64Text := readFile(t, "testdata/25.txt")
	text := decodeBase64(t, string(b64Text))
	res := DecryptECB(text, cipher)
	if err != nil {
		t.Errorf("Error: %s", err)
	}

	// for _, line := range strings.Split(string(res), "\n") {
	// 	t.Logf("%q", line)
	// }

	ct, edit := NewCTREditOracles(res)
	t.Logf("%s", AttackCTREditOracle(ct, edit))

}

func TestNewCTROracles(t *testing.T) {
	generateCookie, amIAdmin := NewCTRCookieOracles()
	if amIAdmin(generateCookie(";admin=true;")) {
		t.Fatal("this is too easy")
	}
	if !amIAdmin(MakeCTRAdminCookie(generateCookie)) {
		t.Error("not admin")
	}
}

func TestNewCBCKeyEqIVOracles(t *testing.T) {
	encryptMessage, decryptMessage, isKeyCorrect := NewCBCKeyEqIVOracles()
	key := RecoverCBCKeyEqIV(encryptMessage, decryptMessage)
	if !isKeyCorrect(key) {
		t.Error("wrong key")
	}
}

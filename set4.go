package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/bits"
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

// SHA1
// https://github.com/golang/go/blob/master/src/crypto/sha1/sha1.go

const (
	chunk = 64
	init0 = 0x67452301
	init1 = 0xEFCDAB89
	init2 = 0x98BADCFE
	init3 = 0x10325476
	init4 = 0xC3D2E1F0
)

// SHA1 represents the partial evaluation of a checksum.
type SHA1 struct {
	h   [5]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

const (
	magic         = "sha\x01"
	marshaledSize = len(magic) + 5*4 + chunk + 8
)

func (d *SHA1) MarshalBinary() ([]byte, error) {
	return d.AppendBinary(make([]byte, 0, marshaledSize))
}

func (d *SHA1) AppendBinary(b []byte) ([]byte, error) {
	b = append(b, magic...)
	b = BeAppendUint32(b, d.h[0])
	b = BeAppendUint32(b, d.h[1])
	b = BeAppendUint32(b, d.h[2])
	b = BeAppendUint32(b, d.h[3])
	b = BeAppendUint32(b, d.h[4])
	b = append(b, d.x[:d.nx]...)
	b = append(b, make([]byte, len(d.x)-d.nx)...)
	b = BeAppendUint64(b, d.len)
	return b, nil
}

func (d *SHA1) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic) || string(b[:len(magic)]) != magic {
		return errors.New("crypto/sha1: invalid hash state identifier")
	}
	if len(b) != marshaledSize {
		return errors.New("crypto/sha1: invalid hash state size")
	}
	b = b[len(magic):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	b, d.len = consumeUint64(b)
	d.nx = int(d.len % chunk)
	return nil
}

func consumeUint64(b []byte) ([]byte, uint64) {
	return b[8:], BeUint64(b)
}

func consumeUint32(b []byte) ([]byte, uint32) {
	return b[4:], BeUint32(b)
}

func (d *SHA1) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.nx = 0
	d.len = 0
}

// New512_224 returns a new [hash.Hash] computing the SHA1 checksum. The Hash
// also implements [encoding.BinaryMarshaler], [encoding.BinaryAppender] and
// [encoding.BinaryUnmarshaler] to marshal and unmarshal the internal
// state of the hash.
func NewSHA1() *SHA1 {
	d := new(SHA1)
	d.Reset()
	return d
}

func (d *SHA1) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			sha1Block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		sha1Block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *SHA1) checkSum() [20]byte {
	len := d.len
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64 + 8]byte // padding + length buffer
	tmp[0] = 0x80
	var t uint64
	if len%64 < 56 {
		t = 56 - len%64
	} else {
		t = 64 + 56 - len%64
	}

	// Length in bits.
	len <<= 3
	padlen := tmp[:t+8]
	BePutUint64(padlen[t:], len)
	d.Write(padlen)

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [20]byte

	BePutUint32(digest[0:], d.h[0])
	BePutUint32(digest[4:], d.h[1])
	BePutUint32(digest[8:], d.h[2])
	BePutUint32(digest[12:], d.h[3])
	BePutUint32(digest[16:], d.h[4])

	return digest
}

// decoding and encoding little and big endian integer types from/to byte slices
// src/internal/byteorder/byteorder.go

func BeUint32(b []byte) uint32 {
	_ = b[3] // bounds check hint to compiler; see golang.org/issue/14808
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}

func BeAppendUint32(b []byte, v uint32) []byte {
	return append(b,
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v),
	)
}

func BePutUint32(b []byte, v uint32) {
	_ = b[3] // early bounds check to guarantee safety of writes below
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func BeUint64(b []byte) uint64 {
	_ = b[7] // bounds check hint to compiler; see golang.org/issue/14808
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}

func BePutUint64(b []byte, v uint64) {
	_ = b[7] // early bounds check to guarantee safety of writes below
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

func BeAppendUint64(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56),
		byte(v>>48),
		byte(v>>40),
		byte(v>>32),
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v),
	)
}

// blockGeneric is a portable, pure Go version of the SHA-1 block step.
// It's used by sha1block_generic.go and tests.
// https://github.com/golang/go/blob/master/src/crypto/sha1/sha1block.go

const (
	_K0 = 0x5A827999
	_K1 = 0x6ED9EBA1
	_K2 = 0x8F1BBCDC
	_K3 = 0xCA62C1D6
)

func sha1Block(dig *SHA1, p []byte) {
	var w [16]uint32

	h0, h1, h2, h3, h4 := dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4]
	for len(p) >= chunk {
		// Can interlace the computation of w with the
		// rounds below if needed for speed.
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}

		a, b, c, d, e := h0, h1, h2, h3, h4

		// Each of the four 20-iteration rounds
		// differs only in the computation of f and
		// the choice of K (_K0, _K1, etc).
		i := 0
		for ; i < 16; i++ {
			f := b&c | (^b)&d
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K0
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}
		for ; i < 20; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = bits.RotateLeft32(tmp, 1)

			f := b&c | (^b)&d
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K0
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}
		for ; i < 40; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = bits.RotateLeft32(tmp, 1)
			f := b ^ c ^ d
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K1
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}
		for ; i < 60; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = bits.RotateLeft32(tmp, 1)
			f := ((b | c) & d) | (b & c)
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K2
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}
		for ; i < 80; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = bits.RotateLeft32(tmp, 1)
			f := b ^ c ^ d
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K3
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e

		p = p[chunk:]
	}

	dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4] = h0, h1, h2, h3, h4
}

// SecretPrefixMAC message authentication code (MAC)
// user for for authenticating and integrity-checking a message
func SecretPrefixMAC(key, message []byte) []byte {
	s := NewSHA1()
	s.Write(key)
	s.Write(message)
	sha1 := s.checkSum()
	return sha1[:]
}

func CheckSecretPrefixMAC(key, message, mac []byte) bool {
	s := NewSHA1()
	s.Write(key)
	s.Write(message)
	sha1 := s.checkSum()
	return bytes.Equal(mac, sha1[:])
}

func MDPadding(len uint64) []byte {
	buf := &bytes.Buffer{}

	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64 + 8]byte // padding + length buffer
	tmp[0] = 0x80
	var t uint64
	if len%64 < 56 {
		t = 56 - len%64
	} else {
		t = 64 + 56 - len%64
	}

	// Length in bits.
	len <<= 3
	padlen := tmp[:t+8]
	BePutUint64(padlen[t:], len)
	buf.Write(padlen)

	return buf.Bytes()
}

func NewSecretPrefixMACOracle() (
	cookie []byte,
	amIAdmin func(cookie []byte) bool,
) {
	key := make([]byte, 16)
	rand.Read(key)

	cookieData := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")

	cookie = append(cookie, SecretPrefixMAC(key, cookieData)...)
	cookie = append(cookie, cookieData...)

	amIAdmin = func(cookie []byte) bool {
		mac := cookie[:20]
		msg := cookie[20:]
		if !CheckSecretPrefixMAC(key, msg, mac) {
			return false
		}
		return bytes.Contains(msg, []byte(";admin=true;")) || strings.HasSuffix(string(msg), ";admin=true")
	}
	return
}

func ExtendSHA1(mac, msg, extension []byte) (newMAC, newMSG []byte) {

	newMSG = append(newMSG, msg...)
	newMSG = append(newMSG, MDPadding(uint64(len(msg)+16))...)

	s := &SHA1{}
	s.h[0] = BeUint32(mac[0:4])
	s.h[1] = BeUint32(mac[4:8])
	s.h[2] = BeUint32(mac[8:12])
	s.h[3] = BeUint32(mac[12:16])
	s.h[4] = BeUint32(mac[16:20])

	s.len = uint64(len(newMSG) + 16)

	// Append the extension
	s.Write(extension)
	newMSG = append(newMSG, extension...)

	// Calculate the new MAC
	sha1 := s.checkSum()
	return sha1[:], newMSG
}

func MakeSHA1AdminCookie(cookie []byte) []byte {
	mac := cookie[:20]
	msg := cookie[20:]

	newMAC, newMSG := ExtendSHA1(mac, msg, []byte(";admin=true"))
	return append(newMAC, newMSG...)
}

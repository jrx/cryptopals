package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	mathrand "math/rand"
	"net/url"
	"strings"
)

// PadPKCS7 pads a byte slice with PKCS#7 padding.
func PadPKCS7(in []byte, size int) []byte {
	if size >= 256 {
		panic("can't pad to size higher than 255")
	}
	padLen := size - len(in)%size
	res := make([]byte, len(in)+padLen)
	copy(res, in)
	for i := len(in); i < len(res); i++ {
		res[i] = byte(padLen)
	}
	return res
}

// EncryptCBC encrypts a byte slice using AES in CBC mode.
func EncryptCBC(b cipher.Block, iv, in []byte) []byte {
	size := b.BlockSize()
	if len(in)%size != 0 {
		log.Fatal("input length must be a multiple of the block size")
	}
	if len(iv) != size {
		log.Fatal("iv length must be equal to the block size")
	}
	out := make([]byte, len(in))
	prev := iv

	for i := 0; i < len(in)/size; i++ {
		copy(out[i*size:], XOR(in[i*size:(i+1)*size], prev))
		b.Encrypt(out[i*size:], out[i*size:])
		prev = out[i*size : (i+1)*size]
	}

	return out
}

// DecryptCBC decrypts a byte slice using AES in CBC mode.
func DecryptCBC(b cipher.Block, iv, in []byte) []byte {
	size := b.BlockSize()
	if len(in)%size != 0 {
		log.Fatal("input length must be a multiple of the block size")
	}
	if len(iv) != size {
		log.Fatal("iv length must be equal to the block size")
	}
	out := make([]byte, len(in))
	prev := iv
	buf := make([]byte, size)
	for i := 0; i < len(in)/size; i++ {
		b.Decrypt(buf, in[i*size:])
		copy(out[i*size:], XOR(buf, prev))
		prev = in[i*size : (i+1)*size]
	}

	return out
}

// EncryptECB encrypts a byte slice using AES in ECB mode.
func EncryptECB(b cipher.Block, in []byte) []byte {
	size := b.BlockSize()
	if len(in)%size != 0 {
		log.Fatal("input length must be a multiple of the block size")
	}
	out := make([]byte, len(in))
	for i := 0; i < len(in); i += size {
		b.Encrypt(out[i:], in[i:])
	}
	return out
}

func NewECBCBCOracle() func([]byte) []byte {
	key := make([]byte, 16)
	rand.Read(key)
	cipher, _ := aes.NewCipher(key)

	return func(in []byte) []byte {

		prefixRNG, _ := rand.Int(rand.Reader, big.NewInt(5))
		prefix := make([]byte, 5+prefixRNG.Int64())
		rand.Read(prefix)

		suffixRNG, _ := rand.Int(rand.Reader, big.NewInt(5))
		suffix := make([]byte, 5+suffixRNG.Int64())
		rand.Read(suffix)

		in = append(append(prefix, in...), suffix...)
		in = PadPKCS7(in, len(in)+16-len(in)%16)

		r, _ := rand.Int(rand.Reader, big.NewInt(2))
		if r.Int64() == 0 {
			iv := make([]byte, 16)
			rand.Read(iv)
			return EncryptCBC(cipher, iv, in)
		} else {
			return EncryptECB(cipher, in)
		}
	}
}

func NewECBSuffixOracle(secret []byte) func([]byte) []byte {
	key := make([]byte, 16)
	rand.Read(key)
	cipher, _ := aes.NewCipher(key)

	return func(in []byte) []byte {
		// time.Sleep(200 * time.Microsecond)
		in = append(in, secret...)
		in = PadPKCS7(in, len(in)+16-len(in)%16)
		return EncryptECB(cipher, in)
	}
}

func RecoverECBSuffix(oracle func([]byte) []byte) []byte {
	bs := 0
	for blockSize := 16; blockSize <= 512; blockSize += 16 {
		msg := bytes.Repeat([]byte{42}, blockSize*2)
		msg = append(msg, 3)
		cipher, err := aes.NewCipher(make([]byte, blockSize))
		if err != nil {
			log.Fatal(err)
		}
		if DetectECB(oracle(msg)[:blockSize*2], cipher) {
			bs = blockSize
			break
		}
	}
	if bs == 0 {
		log.Fatal("could not determine block size")
	}
	log.Printf("Block size is likely: %d", bs)

	buildDict := func(known []byte) map[string]byte {
		dict := make(map[string]byte)

		msg := bytes.Repeat([]byte{42}, bs)
		msg = append(msg, known...)
		msg = append(msg, '?')
		msg = msg[len(msg)-bs:]

		for b := 0; b < 256; b++ {
			msg[bs-1] = byte(b)
			res := string(oracle(msg)[:bs])
			dict[res] = byte(b)
		}
		return dict
	}
	dict := buildDict(nil)
	msg := bytes.Repeat([]byte{42}, bs-1)
	res := string(oracle(msg)[:bs])
	firstByte := dict[res]

	log.Printf("First byte is likely: %c / %v", firstByte, firstByte)

	var plaintext []byte
	for i := 0; i < len(oracle([]byte{})); i++ {
		dict := buildDict(plaintext)
		msg := bytes.Repeat([]byte{42}, Mod(bs-i-1, bs))
		skip := i / bs * bs
		res := string(oracle(msg)[skip : skip+bs])
		plaintext = append(plaintext, dict[res])

		fmt.Printf("%c", dict[res])

	}
	fmt.Println()
	return nil
}

func Mod(a, b int) int {
	return (a%b + b) % b
}

func ProfileFor(email string) string {

	uidRNG, _ := rand.Int(rand.Reader, big.NewInt(90))

	v := url.Values{}
	v.Set("email", email)
	v.Set("uid", fmt.Sprintf("%d", 10+uidRNG.Int64()))
	v.Set("role", "user")
	return v.Encode()
}

func UnpadPKCS7(in []byte) []byte {
	if len(in) == 0 {
		return in
	}
	b := in[len(in)-1]
	if len(in) < int(b) {
		return nil
	}
	for i := 1; i < int(b); i++ {
		if in[len(in)-1-i] != b {
			return nil
		}
	}
	return in[:len(in)-int(b)]
}

func NewCutAndPasteECBOracles() (
	generateCookie func(email string) string,
	amIAdmin func(string) bool,
) {
	key := make([]byte, 16)
	rand.Read(key)
	cipher, _ := aes.NewCipher(key)

	generateCookie = func(email string) string {
		profile := []byte(ProfileFor(email))
		profile = PadPKCS7(profile, len(profile)+16-len(profile)%16)
		cookie := EncryptECB(cipher, profile)
		return string(cookie)
	}

	amIAdmin = func(cookie string) bool {
		profile := UnpadPKCS7(DecryptECB([]byte(cookie), cipher))
		v, err := url.ParseQuery(string(profile))
		if err != nil {
			return false
		}
		log.Print(string(profile))
		return v.Get("role") == "admin"
	}
	return
}

func MakeAdminCookie(generateCookie func(email string) string) string {
	// These could be obtained with RecoverECBSuffix
	start, _ := "email=", "&role=user&uid=51"

	genBlock := func(prefix string) string {
		msg := strings.Repeat("A", 16-len(start)) + prefix
		return generateCookie(msg)[16:32]
	}

	block1 := generateCookie("FOO@BAR.AA")[:16] // email=AAAAAAAAAA
	block2 := genBlock("AAAAAAAAAA")            // AAAAAAAAAA&role=
	block3 := genBlock("admin")                 // admin&role=user&
	msg := strings.Repeat("A", 16-1-len(start)) //
	block4 := generateCookie(msg)[16:48]        // role=user&uid=51 + padding

	// email=AAAAAAAAAAAAAAAAAAAA&role=admin&role=user&role=user&uid=51 + padding
	return block1 + block2 + block3 + block4
}

func NewECBSuffixOracleWithPrefix(secret []byte) func([]byte) []byte {
	key := make([]byte, 16)
	rand.Read(key)
	b, _ := aes.NewCipher(key)
	prefix := make([]byte, mathrand.Intn(100))
	return func(in []byte) []byte {
		// time.Sleep(200 * time.Microsecond)
		rand.Read(prefix)
		msg := append(prefix, append(in, secret...)...)
		return EncryptECB(b, PadPKCS7(msg, 16))
	}
}

// ECBIndex finds the first repeating block
func ECBIndex(in []byte, bs int) int {
	if len(in)%bs != 0 {
		log.Fatal("Wrong sized input")
	}
	prev := in[:bs]
	for i := 1; i < len(in)/bs; i++ {
		if bytes.Equal(prev, in[i*bs:i*bs+bs]) {
			return i*bs - bs
		}
		prev = in[i*bs : i*bs+bs]
	}
	return -1
}

func RecoverECBSuffixWithPrefix(oracle func([]byte) []byte) []byte {
	var bs, pl int
	out := oracle(bytes.Repeat([]byte{42}, 500))
	for blockSize := 2; blockSize < 100; blockSize++ {
		if len(out)%blockSize != 0 {
			continue
		}
		i := ECBIndex(out, blockSize)
		if i < 0 {
			continue
		}
		bs = blockSize
		fmt.Println("bs:", bs)
		for p := 0; p < bs; p++ {
			msg := append(bytes.Repeat([]byte{42}, p+bs*2), 'X')
			if ECBIndex(oracle(msg), bs) == i {
				pl = i - p
				fmt.Println("pl:", pl)
				break
			}
		}
		break
	}
	if bs == 0 || pl == 0 {
		panic("didn't detect block or prefix size")
	}

	return RecoverECBSuffix(func(in []byte) []byte {
		p := bs - pl%bs
		msg := append(bytes.Repeat([]byte{42}, p), in...)
		out := oracle(msg)
		return out[pl+p:]
	})
}

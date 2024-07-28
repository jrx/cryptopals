package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"log"
	mathrand "math/rand"
	"time"
	"unicode"
)

func NewCBCPaddingOracles(plaintext []byte) (
	generateMessage func() []byte,
	checkMessagePadding func(message []byte) bool,
) {
	key := make([]byte, 16)
	rand.Read(key)
	cipher, _ := aes.NewCipher(key)
	generateMessage = func() []byte {
		msg := plaintext
		msg = PadPKCS7(msg, 16)

		// log.Printf("padded: %q", msg[len(msg)-4])

		iv := make([]byte, 16)
		rand.Read(iv)

		ct := EncryptCBC(cipher, iv, msg)
		return append(iv, ct...)
	}
	checkMessagePadding = func(message []byte) bool {
		iv := message[:16]
		msg := message[16:]
		res := UnpadPKCS7(DecryptCBC(cipher, iv, msg))
		return res != nil
	}
	return
}

func AttackCBCPaddingOracle(
	ct []byte,
	checkMessagePadding func(ct []byte) bool) []byte {

	findNextByte := func(known, iv, block []byte) []byte {
		if len(block) != 16 || len(iv) != 16 || len(known) >= 16 {
			panic("wrong lengths for findNextByte")
		}
		payload := make([]byte, 32)
		copy(payload, iv)
		copy(payload[16:], block)
		plaintext := append([]byte{0}, known...)
		for p := 0; p < 256; p++ {
			copy(payload, iv)
			plaintext[0] = byte(p)

			for i := range plaintext {
				payload[len(payload)-1-16-i] ^= plaintext[len(plaintext)-1-i]
			}

			// apply valid padding
			for i := range plaintext {
				payload[len(payload)-1-16-i] ^= byte(len(plaintext))
			}
			// check we actually changed something
			if bytes.Equal(payload[:16], iv) {
				continue
			}
			if checkMessagePadding(payload) {
				return plaintext
			}
		}
		// if the only one that works is not changing anything,
		// there's already a padding of len(plaintext)
		plaintext[0] = byte(len(plaintext))
		for _, c := range plaintext {
			if c != byte(len(plaintext)) {
				plaintext[1] ^= byte(len(plaintext))
				// correct and retry
				return plaintext[1:]
			}
		}
		return plaintext

	}

	if len(ct)%16 != 0 {
		panic("AttackCBCPaddingOracle: invalid ciphertext length")
	}

	var plaintext []byte
	for b := 0; b < len(ct)/16-1; b++ {
		var known []byte
		blockStart := len(ct) - b*16 - 16
		block := ct[blockStart : blockStart+16]
		iv := ct[blockStart-16 : blockStart]
		for len(known) < 16 {
			known = findNextByte(known, iv, block)
			// log.Printf("-> %q", known)
			// time.Sleep(1 * time.Second)
		}

		plaintext = append(known, plaintext...)
	}
	return UnpadPKCS7(plaintext)
}

// EncryptCTR encrypts a byte slice using AES in CTR (Counter) mode.
func EncryptCTR(src []byte, b cipher.Block, nonce []byte) []byte {
	input, output := make([]byte, b.BlockSize()), make([]byte, b.BlockSize())
	copy(input, nonce)
	var dst []byte
	for i := 0; i < len(src); i += b.BlockSize() {
		b.Encrypt(output, input)
		cipherText := XOR(output, src[i:])
		dst = append(dst, cipherText...)

		j := len(nonce)
		for {
			input[j] += 1
			if input[j] != 0 {
				break
			}
			j++
		}
	}
	return dst
}

var DecryptCTR = EncryptCTR

func NewFixedNonceCTROracle() (encryptMessage func([]byte) []byte) {
	key := make([]byte, 16)
	rand.Read(key)
	nonce := make([]byte, 8)
	rand.Read(nonce)
	cipher, _ := aes.NewCipher(key)
	return func(msg []byte) []byte {
		return EncryptCTR(msg, cipher, nonce)
	}
}

func FindFixedNonceCTRKeystream(cipherTexts [][]byte) []byte {
	uppercaseCorpus := make(map[rune]float64)
	for char, value := range corpus {
		if !unicode.IsUpper(char) {
			continue
		}
		uppercaseCorpus[unicode.ToUpper(char)] += value
	}

	column := make([]byte, len(cipherTexts))
	var maxLen int
	for _, ct := range cipherTexts {
		if len(ct) > maxLen {
			maxLen = len(ct)
		}
	}

	keystream := make([]byte, maxLen)
	for col := 0; col < maxLen; col++ {
		var colLen int
		for _, ct := range cipherTexts {
			if col >= len(ct) {
				continue
			}
			column[colLen] = ct[col]
			colLen++
		}

		corp := corpus
		if col == 0 {
			corp = uppercaseCorpus
		}

		_, k, _, err := SingleByteXOR(hex.EncodeToString(column), corp)
		if err != nil {
			log.Fatalf("Error: %s", err)
		}
		keystream[col] = byte(k)
	}
	return keystream
}

type MT19937 struct {
	index int
	mt    [624]uint32
}

func NewMT19937(seed uint32) *MT19937 {
	m := &MT19937{index: 624}

	for i := range m.mt {
		if i == 0 {
			m.mt[0] = seed
		} else {
			m.mt[i] = 1812433253*(m.mt[i-1]^m.mt[i-1]>>30) + uint32(i)
		}
	}
	return m
}

func (m *MT19937) ExtractNumber() uint32 {
	if m.index >= 624 {
		m.Twist()
	}

	y := m.mt[m.index]
	// Right shift by 11 bits
	y ^= y >> 11
	// Shift y left by 7 and take the bitwise and of 2636928640
	y ^= y << 7 & 2636928640
	// Shift y left by 15 and take the bitwise and of y and 4022730752
	y ^= y << 15 & 4022730752
	// Right shift by 18 bits
	y ^= y >> 18

	// log.Printf("got: %d", y)

	m.index++
	return y
}

func (m *MT19937) Twist() {
	for i := range m.mt {
		// Get the most significant bit and add it to the less significant
		// bits of the next number
		y := (m.mt[i] & 0x80000000) + (m.mt[(i+1)%624] & 0x7fffffff)
		m.mt[i] = m.mt[(i+397)%624] ^ y>>1

		if y%2 != 0 {
			m.mt[i] ^= 0x9908b0df
		}
	}
	m.index = 0
}

func RandomNumberFromTimeSeed() (uint32, uint32) {
	time.Sleep(40 * time.Millisecond)
	time.Sleep(time.Duration(mathrand.Intn(1000)) * time.Millisecond)

	seed := uint32(time.Now().UnixMilli())
	n := NewMT19937(seed)

	time.Sleep(40 * time.Millisecond)
	time.Sleep(time.Duration(mathrand.Intn(1000)) * time.Millisecond)

	return n.ExtractNumber(), seed
}

func RecoverTimeSeed(output uint32) uint32 {
	seed := uint32(time.Now().UnixMilli())
	for {
		if NewMT19937(seed).ExtractNumber() == output {
			return seed
		}
		seed--
	}
}

func UntemperMT19937(y uint32) uint32 {
	y ^= y >> 18
	y ^= y << 15 & 4022730752
	for i := 0; i < 7; i++ {
		y ^= y << 7 & 2636928640
	}
	y ^= y>>11 ^ y>>(11*2)
	return y
}

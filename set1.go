package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
)

func HexToBase64(hs string) (string, error) {
	value, err := hex.DecodeString(hs)
	if err != nil {
		return "", err
	}
	log.Printf("%s", value)
	return base64.StdEncoding.EncodeToString(value), nil
}

func FixedXOR(s1, s2 string) (string, error) {
	h1, err := hex.DecodeString(s1)
	if err != nil {
		return "", err
	}
	log.Printf("%s", string(h1))

	h2, err := hex.DecodeString(s2)
	if err != nil {
		return "", err
	}
	log.Printf("%s", string(h2))

	if len(h1) != len(h2) {
		return "", errors.New("invalid length")
	}

	res := make([]byte, len(h1))
	for i := range h1 {
		res[i] = h1[i] ^ h2[i]
	}
	log.Printf("%s", string(res))
	return hex.EncodeToString(res), nil
}

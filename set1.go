package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
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

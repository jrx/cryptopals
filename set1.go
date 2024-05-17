package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"log"
	"os"
)

func BreakSingleByteXOR(file string) (string, error) {
	lines, err := ReadLines(file)
	if err != nil {
		return "", err
	}

	var bestScore float64
	var res string
	for _, line := range lines {
		decryption, _, score, err := SingleByteXOR(line)
		if err != nil {
			return "", err
		}
		// log.Printf("%s", decryption)
		if score > bestScore {
			bestScore = score
			res = decryption
		}
	}
	return res, nil
}

func BreakRepeatingKeyXOR(file string) (string, error) {
	b64text, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	text, err := base64.StdEncoding.DecodeString(string(b64text))
	if err != nil {
		return "", err
	}
	keySize := FindRepeatedKeySize(text)
	log.Printf("Key size is likely: %d", keySize)

	column := make([]byte, (len(text)+keySize-1)/keySize)
	key := make([]byte, keySize)
	for col := 0; col < keySize; col++ {
		for row := range column {
			if row*keySize+col >= len(text) {
				continue
			}
			column[row] = text[row*keySize+col]
		}
		_, k, _, err := SingleByteXOR(hex.EncodeToString(column))
		if err != nil {
			log.Fatalf("Error: %s", err)
		}
		key[col] = byte(k)
	}
	log.Printf("Key is likely: %s", string(key))

	hres, err := RepeatingKeyXOR(string(text), string(key))
	if err != nil {
		return "", err
	}
	res, err := hex.DecodeString(hres)
	if err != nil {
		return "", err
	}
	return string(res), nil
}

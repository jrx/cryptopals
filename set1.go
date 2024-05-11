package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"unicode/utf8"
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

func buildCorpus(text string) map[rune]float64 {
	corpus := make(map[rune]float64)
	for _, char := range text {
		corpus[char]++
	}
	total := utf8.RuneCountInString(text)
	for char := range corpus {
		corpus[char] /= float64(total)
	}
	return corpus
}

func corpusFromFiles(name string) map[rune]float64 {
	text, err := os.ReadFile(name)
	if err != nil {
		log.Fatalf("Error: %s", err)
	}
	return buildCorpus(string(text))
}

func scoreText(text string, corpus map[rune]float64) float64 {
	score := 0.0
	for _, char := range text {
		score += corpus[char]
	}
	return score / float64(utf8.RuneCountInString(text))
}

func SingleByteXOR(s string) (string, error) {
	corpus := corpusFromFiles("alice.txt")
	for char, value := range corpus {
		log.Printf("%c: %.5f", char, value)
	}

	hex, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}

	var res []byte
	var lastScore float64
	for key := 0; key < 256; key++ {

		decryption := make([]byte, len(hex))
		for i, c := range hex {
			decryption[i] = c ^ byte(key)
		}

		score := scoreText(string(decryption), corpus)
		log.Printf("%s: %.5f", string(decryption), score)
		if score > lastScore {
			lastScore = score
			res = decryption
		}
	}
	return string(res), nil
}

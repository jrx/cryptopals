package cryptopals

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"math"
	"math/bits"
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

var corpus = corpusFromFiles("data/alice.txt")

func SingleByteXOR(s string) (string, int, float64, error) {
	// for char, value := range corpus {
	// 	log.Printf("%c: %.5f", char, value)
	// }

	hex, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("Error: %s", err)
	}

	var res []byte
	var bestKey int
	var bestScore float64
	for key := 0; key < 256; key++ {

		decryption := make([]byte, len(hex))
		for i, c := range hex {
			decryption[i] = c ^ byte(key)
		}

		score := scoreText(string(decryption), corpus)
		// log.Printf("%s: %.5f", string(decryption), score)
		if score > bestScore {
			bestKey = key
			bestScore = score
			res = decryption
		}
	}
	return string(res), bestKey, bestScore, nil
}

func readLines(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func DetectSingleByteXOR(file string) (string, error) {
	lines, err := readLines(file)
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

func RepeatingKeyXOR(stext, skey string) (string, error) {
	text := []byte(stext)
	key := []byte(skey)
	res := make([]byte, len(text))
	for i := range text {
		res[i] = text[i] ^ key[i%len(key)]
	}
	return hex.EncodeToString(res), nil
}

func HammingDistance(s1, s2 string) (int, error) {
	b1 := []byte(s1)
	b2 := []byte(s2)
	if len(b1) != len(b2) {
		return 0, errors.New("invalid length")
	}
	distance := 0
	for i := range b1 {
		xor := b1[i] ^ b2[i]
		distance += bits.OnesCount8(xor)
	}
	return distance, nil
}

func FindRepeatedKeySize(cipher []byte) int {
	var result int
	var bestScore float64 = math.MaxFloat64
	for keySize := 2; keySize <= 40; keySize++ {
		s1 := cipher[:keySize*8]
		s2 := cipher[keySize*8 : keySize*8*2]

		distance, err := HammingDistance(string(s1), string(s2))
		if err != nil {
			log.Fatalf("Error: %s", err)
		}

		score := float64(distance) / float64(keySize)
		// log.Printf("Key size: %d, Score: %.5f", keySize, score)
		if score < bestScore {
			bestScore = score
			result = keySize
		}
	}
	return result
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

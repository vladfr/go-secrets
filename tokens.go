package secrets

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

//Token is a cryptographically secure generated token with crc
type Token struct {
	token  string
	prefix string
	b      []byte
	crc    string
	Valid  bool
	err    error
}

func (t Token) Err() error {
	return t.err
}

func (t Token) String() string {
	return t.prefix + t.token
}

func (t Token) Prefix() string {
	return t.prefix
}

func (t Token) Len() int {
	return len(t.String())
}

func (t Token) Base62() string {
	return t.prefix + toBase62(t.token)
}

func genToken(n int) ([]byte, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	const lettersSize = byte(len(letters))
	randBytes := make([]byte, n)

	_, err := rand.Read(randBytes)
	for k, v := range randBytes {
		randBytes[k] = letters[v%lettersSize]
	}

	return randBytes, err
}

//https://ucarion.com/go-base62
func toBase62(s string) string {
	var i big.Int
	i.SetBytes([]byte(s))
	return i.Text(62)
}

func parseBase62(s string) ([]byte, error) {
	var i big.Int
	_, ok := i.SetString(s, 62)
	if !ok {
		return make([]byte, 0), fmt.Errorf("cannot parse base62: %q", s)
	}

	return i.Bytes(), nil
}

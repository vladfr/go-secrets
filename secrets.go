package secrets

import (
	"crypto/rand"
	"fmt"
	"hash/crc32"
	"math/big"
)

//crLen is the length of the crc checksum that we keep in the token
const crcLen = 6

//Token is a cryptographically secure generated token with crc
type Token struct {
	token string
	b     []byte
	crc   string
	Valid bool
}

func (t Token) String() string {
	return t.token
}

func (t Token) Len() int {
	return len(t.token)
}

func (t Token) Base62() string {
	return toBase62(t.token)
}

func makeToken(b []byte) Token {
	crcIndex := len(b) - crcLen
	sum := b[crcIndex:]
	r := b[:crcIndex]
	return Token{
		token: string(b),
		b:     r,
		crc:   string(sum),
	}
}

//Validate returns true if the crc is valid
func Validate(t Token) bool {
	return Checksum(t.b) == t.crc
}

//Checksum calculates the crc32 sum of the token
func Checksum(data []byte) string {
	sum := crc32.ChecksumIEEE(data)
	pad := fmt.Sprintf("%06d", sum)
	return pad[:crcLen]
}

//NewToken generates a new token together with its crc32
func NewToken(len int) (Token, error) {
	b, err := genToken(len)

	if err != nil {
		return Token{}, err
	}

	crc := Checksum(b)
	full := fmt.Sprintf("%s%06s", b, crc)

	return Token{
		token: full,
		b:     b,
		crc:   crc,
		Valid: true,
	}, err
}

//TokenFromString builds Token object from a given string; also validates the crc32
func TokenFromString(s string) Token {
	t := makeToken([]byte(s))
	t.Valid = Validate(t)
	return t
}

//TokenFromBase62 builds Token object from a base62-encoded string; also validates the crc32
func TokenFromBase62(s string) (Token, error) {
	b, err := parseBase62(s)
	if err != nil {
		return Token{}, err
	}
	t := makeToken(b)
	t.Valid = Validate(t)
	return t, err
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

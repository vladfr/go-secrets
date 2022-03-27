package secrets

import (
	"errors"
	"fmt"
	"hash/crc32"
)

type TokenConfig struct {
	Len    int
	CrcLen int
	Prefix string
}

type TokenFactory struct {
	cfg TokenConfig
}

var ConfigDefault = TokenConfig{
	Len:    30,
	CrcLen: 6,
	Prefix: "",
}

func NewTokenFactory(config TokenConfig) *TokenFactory {
	return &TokenFactory{
		cfg: config,
	}
}

// FromString builds Token object from a given string; also validates the crc32
func (f *TokenFactory) FromString(s string) Token {
	return f.makeToken(s, func(s string) ([]byte, error) {
		return []byte(s), nil
	})
}

//FromBase62 builds Token object from a base62-encoded string; also validates the crc32
func (f *TokenFactory) FromBase62(s string) Token {
	return f.makeToken(s, parseBase62)
}

type parseFunc func(string) ([]byte, error)

func (f *TokenFactory) makeToken(s string, parser parseFunc) Token {
	t := Token{
		token:  s,
		prefix: "",
		Valid:  false,
	}

	// split prefix and token
	prLen := len(f.cfg.Prefix)
	t.prefix = s[:prLen]
	t.token = string(s[prLen:])

	// parse token with parser function
	token, err := parser(s[prLen:])
	if err != nil {
		t.err = err
		return t
	}

	if len(token) != f.cfg.Len+f.cfg.CrcLen {
		// token has wrong length
		t.Valid = false
		t.err = errors.New("invalid length")
		return t
	} else if t.prefix != f.cfg.Prefix {
		// token has wrong prefix
		t.Valid = false
		t.err = errors.New("invalid prefix")
		return t
	}

	// split crc
	crcIndex := len(token) - f.cfg.CrcLen
	sum := token[crcIndex:]
	r := token[:crcIndex]
	t.token = string(token)
	t.b = r
	t.crc = string(sum)

	isValid := f.Validate(t)
	t.Valid = isValid
	if !isValid {
		t.err = errors.New("invalid crc")
	}

	return t
}

//NewToken generates a new token and returns a Token object.
// Any errors are captured and can be accessed with Err()

// Tokens contain a CRC32 checksum controlled by the CrcLen parameter.
// When using FromString() or FromBase62(), the factory validates tokens with their crc32
// based on the factory config.
func (f *TokenFactory) NewToken() Token {
	b, err := genToken(f.cfg.Len)

	if err != nil {
		return Token{
			Valid: false,
			err:   err,
		}
	}

	crc := f.Checksum(b)
	full := fmt.Sprintf("%s%0*s", b, f.cfg.CrcLen, crc)

	return Token{
		token:  full,
		b:      b,
		crc:    crc,
		prefix: f.cfg.Prefix,
		Valid:  true,
		err:    nil,
	}
}

//Validate returns true if the crc is valid
func (f *TokenFactory) Validate(t Token) bool {
	return f.Checksum(t.b) == t.crc
}

//Checksum calculates the crc32 sum of the token
func (f *TokenFactory) Checksum(data []byte) string {
	sum := crc32.ChecksumIEEE(data)
	pad := fmt.Sprintf("%0*d", f.cfg.CrcLen, sum)
	return pad[:f.cfg.CrcLen]
}

package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewToken(t *testing.T) {
	token, err := NewToken(30)
	assert.NoError(t, err)
	assert.Equal(t, 36, token.Len())
	assert.NotEmpty(t, token.String())
	assert.NotEmpty(t, token.Base62())
}

func TestFromString(t *testing.T) {
	token, err := NewToken(30)
	assert.NoError(t, err)

	tokenFromS := TokenFromString(token.String())

	assert.Equal(t, token.String(), tokenFromS.String())
	assert.True(t, tokenFromS.Valid)
}

func TestFromBase62(t *testing.T) {
	token, err := NewToken(30)
	assert.NoError(t, err)

	token62, err := TokenFromBase62(token.Base62())
	assert.NoError(t, err)

	assert.Equal(t, token.String(), token62.String())
	assert.True(t, token62.Valid)
}

func TestValidate(t *testing.T) {
	token, _ := NewToken(30)
	assert.True(t, Validate(token))
}

func TestB62(t *testing.T) {
	s := "This is 1 test string"

	enc := toBase62(s)
	assert.NotEmpty(t, enc)
	assert.EqualValues(t, "NJaT6B7Ip2oLiysprlOr8RVjFRr1", enc)

	dec, err := parseBase62(enc)
	assert.NoError(t, err)
	assert.EqualValues(t, s, string(dec))
}

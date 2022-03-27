package secrets

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFactoryNewToken(t *testing.T) {
	f := NewTokenFactory(ConfigDefault)
	token := f.NewToken()
	assert.NoError(t, token.Err())
	assert.NotEmpty(t, token.String())
	assert.Equal(t, 36, token.Len())
	assert.True(t, token.Valid)
	assert.Regexp(t, regexp.MustCompile("^[a-zA-Z0-9]{30}[0-9]{6}$"), token.String())
}

func TestFactoryInvalidCrc(t *testing.T) {
	f := NewTokenFactory(ConfigDefault)
	token := f.NewToken()
	assert.NoError(t, token.Err())

	s := token.String()
	token2 := f.FromString(s[:30] + "000006")
	assert.ErrorContains(t, token2.Err(), "invalid crc")
}

func TestFactoryNewTokenWithPrefix(t *testing.T) {
	f := NewTokenFactory(TokenConfig{
		Len:    30,
		CrcLen: 6,
		Prefix: "bzt_",
	})
	token := f.NewToken()
	assert.NoError(t, token.Err())
	assert.True(t, token.Valid)
	assert.EqualValues(t, "bzt_", token.Prefix())
	assert.Regexp(t, regexp.MustCompile("^bzt_[a-zA-Z0-9]{30}[0-9]{6}$"), token.String())
}

func TestFactoryValidString(t *testing.T) {
	f := NewTokenFactory(TokenConfig{
		Len:    30,
		CrcLen: 6,
		Prefix: "bzt_",
	})

	token := f.NewToken()
	assert.NoError(t, token.Err())

	token2 := f.FromString(token.String())
	assert.NoError(t, token2.Err())
	assert.True(t, token2.Valid, token2.String())
	assert.EqualValues(t, "bzt_", token2.Prefix())
	assert.Regexp(t, regexp.MustCompile("^bzt_[a-zA-Z0-9]{30}[0-9]{6}$"), token2.String())
}

func TestFactoryValidBase62(t *testing.T) {
	f := NewTokenFactory(TokenConfig{
		Len:    30,
		CrcLen: 6,
		Prefix: "bzt_",
	})

	token := f.NewToken()
	assert.NoError(t, token.Err())

	token2 := f.FromBase62(token.Base62())
	assert.NoError(t, token2.Err())
	assert.True(t, token2.Valid, token2.String())
	assert.EqualValues(t, "bzt_", token2.Prefix())
	assert.Regexp(t, regexp.MustCompile("^bzt_[a-zA-Z0-9]{30}[0-9]{6}$"), token2.String())
}

func TestFactoryInvalidLen(t *testing.T) {
	f := NewTokenFactory(TokenConfig{
		Len:    30,
		CrcLen: 6,
		Prefix: "bzt_",
	})

	token := f.NewToken()
	assert.NoError(t, token.Err())

	token2 := f.FromString(token.String() + "wrong")
	assert.ErrorContains(t, token2.Err(), "length")
	assert.False(t, token2.Valid, token2.String())
}

func TestFactoryInvalidPrefix(t *testing.T) {
	f := NewTokenFactory(TokenConfig{
		Len:    30,
		CrcLen: 6,
		Prefix: "bzt_",
	})

	token := f.NewToken()
	assert.NoError(t, token.Err())

	token2 := f.FromString("wro_" + token.String()[4:])
	assert.ErrorContains(t, token2.Err(), "prefix")
	assert.False(t, token2.Valid, token2.String())
}

func TestFactoryInvalidBase62(t *testing.T) {
	f := NewTokenFactory(TokenConfig{
		Len:    30,
		CrcLen: 6,
		Prefix: "bzt_",
	})

	token := f.NewToken()
	assert.NoError(t, token.Err())

	b62 := token.Base62()
	token2 := f.FromBase62(b62[:3] + "rando$" + b62[9:])
	assert.ErrorContains(t, token2.Err(), "cannot parse base62")
	assert.False(t, token2.Valid, token2.String())
}

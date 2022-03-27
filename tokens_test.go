package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestB62(t *testing.T) {
	s := "This is 1 test string"

	enc := toBase62(s)
	assert.NotEmpty(t, enc)
	assert.EqualValues(t, "NJaT6B7Ip2oLiysprlOr8RVjFRr1", enc)

	dec, err := parseBase62(enc)
	assert.NoError(t, err)
	assert.EqualValues(t, s, string(dec))
}

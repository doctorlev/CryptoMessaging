package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Testing correct encryption of the Text+Pass to Hash
func TestEncryptMatch(t *testing.T) {
	// t.Log("Hi")
	in := EncryptRequest{
		Text: "Hello",
		Pass: "333",
	}
	ret, err := encryptData(in) // encrypting Text+Pass to ret

	assert.Nil(t, err)    // error === nil ? if not - TEST FAILED
	assert.NotNil(t, ret) // ret !== nil ?
	// t.Log(ret)
	assert.Equal(t, "voDZE50wPZJLkZv1fOZoYA==", ret.Hash) // comparison result (match)
}

// Testing wrong encryption failure
func TestEncryptBad(t *testing.T) {
	// t.Log("Hi")
	in := EncryptRequest{
		Text: "Fail",
		Pass: "333",
	}
	ret, err := encryptData(in)

	assert.Nil(t, err)
	assert.NotNil(t, ret)
	// t.Log(ret)
	assert.NotEqual(t, "voDZE50wPZJLkZv1fOZoYA==", ret.Hash) // compares (not matching)
}
func TestEncryptEmptyPass(t *testing.T) {
	// t.Log("Hi")
	in := EncryptRequest{
		Text: "NoPass",
		Pass: "",
	}
	ret, err := encryptData(in)

	assert.NotNil(t, err) // error if not-nil result !
	assert.Nil(t, ret)
	t.Log(ret)
}

// func TestEncryptEmpty(t *testing.T) {
// 	// t.Log("Hi")
// 	in := EncryptRequest{}
// 	ret, err := encryptData(in)

// 	assert.NotNil(t, err)
// 	assert.Nil(t, ret)
// }

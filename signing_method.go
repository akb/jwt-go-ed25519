package ed25519

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

var (
	ErrorInvalidPublicKey   = fmt.Errorf("key is not an Ed25519	public key")
	ErrorInvalidPrivateKey  = fmt.Errorf("key is not an Ed25519 private key")
	ErrorInauthenticMessage = fmt.Errorf("message is inauthentic")
)

var (
	EncodeToString = base64.StdEncoding.EncodeToString
	DecodeString   = base64.StdEncoding.DecodeString
)

var SigningMethod *SigningMethodEd25519

func init() {
	SigningMethod = &SigningMethodEd25519{}
	jwt.RegisterSigningMethod(SigningMethod.Alg(), func() jwt.SigningMethod {
		return SigningMethod
	})
}

type SigningMethodEd25519 struct{}

func (SigningMethodEd25519) Verify(message, signature string, key interface{}) error {
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return ErrorInvalidPublicKey
	}

	signatureBytes, err := DecodeString(signature)
	if err != nil {
		return err
	}

	if !ed25519.Verify(publicKey, []byte(message), signatureBytes) {
		return ErrorInauthenticMessage
	}
	return nil
}

func (SigningMethodEd25519) Sign(message string, key interface{}) (string, error) {
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return "", ErrorInvalidPrivateKey
	}

	return EncodeToString(ed25519.Sign(privateKey, []byte(message))), nil
}

func (SigningMethodEd25519) Alg() string {
	return "Ed25519"
}

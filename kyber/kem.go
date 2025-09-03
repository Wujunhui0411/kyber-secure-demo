// kyber/kem.go
package kyber

import (
	"fmt"

	"github.com/cloudflare/circl/kem"
	kyber1024 "github.com/cloudflare/circl/kem/kyber/kyber1024"
	kyber512 "github.com/cloudflare/circl/kem/kyber/kyber512"
	kyber768 "github.com/cloudflare/circl/kem/kyber/kyber768"
)

// schemeFromLevel maps 512/768/1024 to CIRCL schemes.
func schemeFromLevel(level int) (kem.Scheme, error) {
	switch level {
	case 512:
		return kyber512.Scheme(), nil
	case 768:
		return kyber768.Scheme(), nil
	case 1024:
		return kyber1024.Scheme(), nil
	default:
		return nil, fmt.Errorf("unsupported Kyber level: %d (use 512/768/1024)", level)
	}
}

// KeyGen generates a real Kyber keypair using CIRCL and wraps it into our types.
func KeyGen(level int) (*PublicKey, *PrivateKey, error) {
	s, err := schemeFromLevel(level)
	if err != nil {
		return nil, nil, err
	}
	pk, sk, err := s.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return &PublicKey{scheme: s, inner: pk, real: true}, &PrivateKey{scheme: s, inner: sk, real: true}, nil
}

// Encapsulate performs KEM encapsulation using the wrapped public key.
func Encapsulate(pk *PublicKey) (ct, ss []byte, err error) {
	if pk == nil || pk.inner == nil || pk.scheme == nil {
		return nil, nil, fmt.Errorf("public key is nil or not initialized; call KeyGen first")
	}
	return pk.scheme.Encapsulate(pk.inner)
}

// DecapsulateRaw performs plain decapsulation if a real key is present.
func DecapsulateRaw(ct []byte, sk *PrivateKey) ([]byte, error) {
	if sk == nil || sk.inner == nil || sk.scheme == nil {
		return nil, fmt.Errorf("private key is nil or not initialized; call KeyGen first")
	}
	return sk.scheme.Decapsulate(sk.inner, ct)
}

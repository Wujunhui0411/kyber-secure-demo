package kyber

import (
	"github.com/cloudflare/circl/kem/kyber/kyber512"
)

func SimpleDecapsulate(sk *kyber512.PrivateKey, ct []byte) ([]byte, error) {
	scheme := kyber512.Scheme()
	return scheme.Decapsulate(sk, ct)
}

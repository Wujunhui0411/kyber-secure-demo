package kyber

import (
    "github.com/cloudflare/circl/kem/kyber"
)

var scheme = kyber.Kyber512

func SecureDecapsulate(sk kyber.PrivateKey, ct []byte) ([]byte, error) {
    return scheme.Decapsulate(sk, ct)
}

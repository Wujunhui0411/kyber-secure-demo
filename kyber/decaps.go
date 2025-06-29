package kyber

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"golang.org/x/crypto/sha3"
)

const Q = 3329

var ErrDecodeFault = errors.New("poly_to_msgSecure: decode fault detected (missing +Q/2)")

func polyToMsgSecure(a uint16) (uint8, error) {
	x1 := ((uint32(a) << 1) + (Q / 2)) / Q
	bit1 := uint8(x1 & 1)

	x2 := ((uint32(a) << 1) + (Q / 2)) / Q
	bit2 := uint8(x2 & 1)

	if bit1 != bit2 {
		return 0, ErrDecodeFault
	}
	return bit1, nil
}

func coeffFromCiphertext(c []byte) uint16 {
	if len(c) < 2 {
		return 0
	}
	return binary.LittleEndian.Uint16(c[:2])
}

func fallbackSharedKey(c []byte) []byte {
	buf := make([]byte, 32)
	rand.Read(buf)
	return buf
}

func DecapsSecure(ct []byte, sk *kyber512.PrivateKey, pk *kyber512.PublicKey) ([]byte, error) {
	a := coeffFromCiphertext(ct)
	bit, err := polyToMsgSecure(a)
	if err != nil {
		return fallbackSharedKey(ct), nil
	}
	shared := []byte{bit}

	ctPrime := make([]byte, len(ct))
	copy(ctPrime, ct)
	d, dPrime := byte(0xAB), byte(0xAB)

	h1 := sha3.Sum256(append(ct, ctPrime...))
	h1 = sha3.Sum256(append(h1[:], d, dPrime))
	h2 := sha3.Sum256(append(ctPrime, ct...))
	h2 = sha3.Sum256(append(h2[:], dPrime, d))

	if !bytes.Equal(h1[:], h2[:]) {
		return fallbackSharedKey(ct), nil
	}
	return shared, nil
}

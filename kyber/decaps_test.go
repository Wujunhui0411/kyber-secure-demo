package kyber

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
)

func TestPolyToMsgSecure(t *testing.T) {
	a := uint16(833)
	bit, err := polyToMsgSecure(a)
	if err != nil {
		t.Fatalf("Unexpected decode fault: %v", err)
	}

	expected := uint8((((uint32(a) << 1) + (Q / 2)) / Q) & 1)
	if bit != expected {
		t.Fatalf("Expected %d, got %d", expected, bit)
	}
}

func TestDecapsSecureFallback(t *testing.T) {
	sk := &kyber512.PrivateKey{}
	pk := &kyber512.PublicKey{}

	a := uint16(Q / 4)
	ct := make([]byte, 32)
	binary.LittleEndian.PutUint16(ct[:2], a)
	shared1, _ := DecapsSecure(ct, sk, pk)

	binary.LittleEndian.PutUint16(ct[:2], uint16(833)) // fault case
	shared2, _ := DecapsSecure(ct, sk, pk)

	if bytes.Equal(shared1, shared2) {
		t.Fatal("Fallback expected on decode fault, but got same shared key")
	}
}

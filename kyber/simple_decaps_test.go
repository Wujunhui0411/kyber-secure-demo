package kyber

import (
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
)

func TestSimpleDecapsulate(t *testing.T) {
	scheme := kyber512.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatal("KeyGen failed:", err)
	}

	ct, ss1, err := scheme.Encapsulate(pk)
	if err != nil {
		t.Fatal("Encapsulate failed:", err)
	}

	ss2, err := SimpleDecapsulate(sk, ct)
	if err != nil {
		t.Fatal("Decapsulate failed:", err)
	}

	if string(ss1) != string(ss2) {
		t.Fatal("Shared secret mismatch")
	}
}

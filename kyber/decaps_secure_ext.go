// kyber/decaps_secure_ext.go
package kyber

// DecapsulateExt decapsulates with either secure or original path.
// Deprecated: Use DecapsulateSecure (secure=true) or Decapsulate (secure=false) instead.
func DecapsulateExt(c []byte, sk *PrivateKey, pk *PublicKey, secure bool) ([]byte, error) {
	if secure {
		return DecapsSecure(c, sk, pk)
	}
	return DecapsulateOriginal(c, sk, pk)
}

// DecapsulateSecure performs hardened decapsulation.
// It never exposes detailed failure causes; on anomaly it returns a 32-byte fallback key.
func DecapsulateSecure(c []byte, sk *PrivateKey, pk *PublicKey) ([]byte, error) {
	return DecapsSecure(c, sk, pk)
}

// Decapsulate performs plain/original decapsulation (no extra hardening).
func Decapsulate(c []byte, sk *PrivateKey, pk *PublicKey) ([]byte, error) {
	return DecapsulateOriginal(c, sk, pk)
}

// DecapsulateOriginal: if real key exists, call CIRCL decapsulation.
// Otherwise (demo path), derive a single bit from ciphertext[:2] using (+Q/2) rounding.
func DecapsulateOriginal(c []byte, sk *PrivateKey, pk *PublicKey) ([]byte, error) {
	// Real Kyber path via CIRCL when keys are initialized.
	if sk != nil && sk.scheme != nil && sk.inner != nil {
		return sk.scheme.Decapsulate(sk.inner, c)
	}

	// Demo path: extract a 16-bit coefficient and compute a single bit.
	a := coeffFromCiphertext(c)
	bit := uint8((((uint32(a) << 1) + (Q / 2)) / Q) & 1)
	return []byte{bit}, nil
}

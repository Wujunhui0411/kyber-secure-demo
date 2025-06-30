package kyber

// Package 裝飾 Secure 解封裝邏輯，用於 CLI / benchmark 調用

// DecapsulateExt 使用 Secure 或普通方式解封裝
func DecapsulateExt(c []byte, sk *PrivateKey, pk *PublicKey, secure bool) ([]byte, error) {
	if secure {
		return DecapsSecure(c, sk, pk)
	}
	return DecapsulateOriginal(c, sk, pk)
}

// DecapsulateOriginal 示意：原始解封裝，這裡簡化實作
func DecapsulateOriginal(c []byte, sk *PrivateKey, pk *PublicKey) ([]byte, error) {
	a := coeffFromCiphertext(c)
	bit := uint8(((uint32(a) << 1) + (Q / 2)) / Q & 1)
	return []byte{bit}, nil
}

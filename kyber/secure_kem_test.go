package kyber

import (
	"bytes"
	"testing"
)

// 破壞 ciphertext 誘發異常，驗證 secure 模式不回錯而走 fallback（真實 Kyber 路徑）
func TestDecap_Secure_FallbackOnCorruptedCiphertext_Real(t *testing.T) {
	pk, sk, err := KeyGen(1024)
	if err != nil {
		t.Fatal(err)
	}
	ct, ssEnc, err := Encapsulate(pk)
	if err != nil {
		t.Fatal(err)
	}

	bad := make([]byte, len(ct))
	copy(bad, ct)
	bad[0] ^= 0x01 // flip 1 bit

	ssDec, err := DecapsulateExt(bad, sk, pk, true)
	if err != nil {
		t.Fatalf("secure decap should not error on corrupted ct; got %v", err)
	}
	if bytes.Equal(ssEnc, ssDec) {
		t.Fatalf("expected fallback key (different from sender key) on corrupted ct")
	}
	if len(ssDec) != 32 {
		t.Fatalf("fallback key length = %d, want 32", len(ssDec))
	}
}

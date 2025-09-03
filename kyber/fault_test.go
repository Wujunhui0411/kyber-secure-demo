//go:build fault
// +build fault

package kyber

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// 1) 驗證 poly_to_msgSecure 真的能偵測：a=833 時跳過 +Q/2 會報 ErrDecodeFault
func TestPolyToMsgSecure_FaultDetected(t *testing.T) {
	const a uint16 = 833 // 你的範例
	EnableSkipHalfQ()
	t.Cleanup(DisableSkipHalfQ)

	_, err := poly_to_msgSecure(a)
	if err == nil {
		t.Fatalf("expected ErrDecodeFault when skipping +Q/2, got nil")
	}
	if err != ErrDecodeFault {
		t.Fatalf("unexpected error: %v", err)
	}
}

// 2) 驗證 DecapsSecure 會在故障時走 fallback（demo 路徑：沒有真實 key）
func TestDecapsSecure_FallbackOnFault_Demo(t *testing.T) {
	sk := &PrivateKey{} // 無 scheme → 走 demo 路徑
	pk := &PublicKey{}

	// 正常情況：a=Q/4 → 不觸發故障 → 回 1 byte
	aNormal := uint16(Q / 4)
	cNormal := make([]byte, 2)
	binary.LittleEndian.PutUint16(cNormal, aNormal)
	DisableSkipHalfQ()
	ssNormal, err := DecapsulateExt(cNormal, sk, pk, true)
	if err != nil {
		t.Fatalf("normal decap error: %v", err)
	}
	if len(ssNormal) != 1 {
		t.Fatalf("demo normal key should be 1 byte, got %d", len(ssNormal))
	}

	// 故障情況：a=833 + 跳過 +Q/2 → fallback 32 bytes
	aFault := uint16(833)
	cFault := make([]byte, 2)
	binary.LittleEndian.PutUint16(cFault, aFault)
	EnableSkipHalfQ()
	t.Cleanup(DisableSkipHalfQ)

	ssFault, err := DecapsulateExt(cFault, sk, pk, true)
	if err != nil {
		t.Fatalf("secure decap should not error on fault; got %v", err)
	}
	if bytes.Equal(ssNormal, ssFault) {
		t.Fatalf("fallback key should differ from normal output")
	}
	if len(ssFault) != 32 {
		t.Fatalf("fallback key length = %d, want 32", len(ssFault))
	}
}

package kyber

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDecapsulateExt_SecureVsOriginal(t *testing.T) {
	sk := &PrivateKey{}
	pk := &PublicKey{}

	a := uint16(Q / 4)
	c := make([]byte, 32)
	binary.LittleEndian.PutUint16(c[:2], a)

	// Secure
	sharedSecure, err := DecapsulateExt(c, sk, pk, true)
	if err != nil {
		t.Fatalf("Secure 解封裝錯誤: %v", err)
	}

	// Original
	sharedOrig, err := DecapsulateExt(c, sk, pk, false)
	if err != nil {
		t.Fatalf("原始解封裝錯誤: %v", err)
	}

	// 若無攻擊，兩者結果應相同
	if !bytes.Equal(sharedSecure, sharedOrig) {
		t.Fatalf("Secure 與原始解封裝結果不同")
	}
}

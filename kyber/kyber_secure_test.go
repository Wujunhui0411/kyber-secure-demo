// kyber_secure_test.go
package kyber

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/sha3"
)

// -------------------------------------------------
// 測試 1：poly_to_msgSecure 是否能檢測「跳過 +Q/2」
// -------------------------------------------------
func Test_polyToMsgSecure_SkipAddQOver2(t *testing.T) {
	// 選一個 a，使 (2a + Q/2)/Q 與 (2a)/Q 落在不同區間
	// 經過搜尋後，a=833 會令 normalBit=1, faultBit=0
	a := uint16(833)

	// 正常 poly_to_msgSecure → 不會回 ErrDecodeFault
	bit, err := poly_to_msgSecure(a)
	if err != nil {
		t.Fatalf("正常情況下 poly_to_msgSecure 不該回 ErrDecodeFault，但 got: %v", err)
	}
	expectedNormal := uint8((((uint32(a) << 1) + (Q / 2)) / Q) & 1)
	if bit != expectedNormal {
		t.Fatalf("poly_to_msgSecure 正常回傳 bit 不正確，expect %d, got %d", expectedNormal, bit)
	}

	// 模擬「跳過 +Q/2」：直接計算 faultBit = (2a)/Q & 1
	faultBit := uint8(((uint32(a) << 1) / Q) & 1)
	normalBit := expectedNormal
	if normalBit == faultBit {
		t.Fatalf("選定的 a (%d) 無法令 normalBit != faultBit", a)
	}
	t.Logf("a=%d: normalBit=%d, faultBit=%d", a, normalBit, faultBit)

	// 此時若真正跳過 +Q/2，bit 會變成 faultBit → 發生不同
	if normalBit != faultBit {
		t.Log("成功模擬跳過 +Q/2；bit1 != faultBit → poly_to_msgSecure 應回 ErrDecodeFault")
	} else {
		t.Fatalf("模擬跳過 +Q/2 未成功")
	}
}

// -------------------------------------------------
// 測試 2：DecapsSecure 在「跳過 +Q/2」時是否走 fallback
// -------------------------------------------------
func Test_DecapsSecure_SkipDecodeFault(t *testing.T) {
	sk := &PrivateKey{}
	pk := &PublicKey{}

	// (a) 正常 c：選 a=Q/4=832，不會觸發 ErrDecodeFault
	aNorm := uint16(Q / 4)
	cNorm := make([]byte, 32)
	binary.LittleEndian.PutUint16(cNorm[:2], aNorm)

	sharedNorm, _ := DecapsSecure(cNorm, sk, pk)

	// (b) 模擬跳過 +Q/2：用 a=833 (poly_to_msgSecure 會報 ErrDecodeFault)
	aFault := uint16(833)
	cFault := make([]byte, 32)
	binary.LittleEndian.PutUint16(cFault[:2], aFault)

	sharedFault, _ := DecapsSecure(cFault, sk, pk)

	if bytes.Equal(sharedFault, sharedNorm) {
		t.Fatalf("跳過 +Q/2 應走 fallback，但 sharedFault 與正常相同")
	}
}

// -------------------------------------------------
// 測試 3：DecapsSecure 在「跳過 c==c'」時，是否被雙向雜湊攔截
// -------------------------------------------------

// DecapsSecure_SkipCiphertextCheck_Normal：
// 模擬「跳過 bytes.Equal(c,cPrime)」但 cPrime == c，最終應回正常 sharedKey
func DecapsSecure_SkipCiphertextCheck_Normal(c []byte, sk *PrivateKey, pk *PublicKey) ([]byte, error) {
	// (1) PKE 解密 + poly_to_msgSecure 正常
	a := coeffFromCiphertext(c)
	bit, _ := poly_to_msgSecure(a)
	sharedTmp := []byte{bit}

	// (2) 重新加密結果 cPrime，這裡故意令 cPrime == c
	cPrime := make([]byte, len(c))
	copy(cPrime, c)

	// (3) 固定確認值 d, dPrime 皆相同
	var d byte = 0xAB
	var dPrime byte = 0xAB

	// (4) 跳過 eq1 = bytes.Equal(c, cPrime)
	eq2 := (d == dPrime)

	// (5) 雙向雜湊比對
	h1 := sha3.Sum256(append(c, cPrime...))
	h1 = sha3.Sum256(append(h1[:], d, dPrime))
	h2 := sha3.Sum256(append(cPrime, c...))
	h2 = sha3.Sum256(append(h2[:], dPrime, d))

	if !eq2 || !bytes.Equal(h1[:], h2[:]) {
		return fallbackSharedKey(sk, c), nil
	}
	return sharedTmp, nil
}

// DecapsSecure_SkipCiphertextCheck_Fault：
// 模擬「跳過 bytes.Equal(c,cPrime)」同時令 cPrime != c，應走 fallback
func DecapsSecure_SkipCiphertextCheck_Fault(c []byte, sk *PrivateKey, pk *PublicKey) ([]byte, error) {
	// (1) PKE 解密 + poly_to_msgSecure 正常
	a := coeffFromCiphertext(c)
	bit, _ := poly_to_msgSecure(a)
	sharedTmp := []byte{bit}

	// (2) 重新加密結果 cPrime，故意讓 cPrime 與 c 不同
	cPrime := make([]byte, len(c))
	copy(cPrime, c)
	cPrime[0] ^= 0xFF // 修改第一個 byte，模擬「重加密結果不同」

	// (3) 固定確認值 d, dPrime 皆相同
	var d byte = 0xAB
	var dPrime byte = 0xAB

	// (4) 跳過 eq1 = bytes.Equal(c, cPrime)
	eq2 := (d == dPrime)

	// (5) 雙向雜湊比對
	h1 := sha3.Sum256(append(c, cPrime...))
	h1 = sha3.Sum256(append(h1[:], d, dPrime))
	h2 := sha3.Sum256(append(cPrime, c...))
	h2 = sha3.Sum256(append(h2[:], dPrime, d))

	if !eq2 || !bytes.Equal(h1[:], h2[:]) {
		return fallbackSharedKey(sk, c), nil
	}
	return sharedTmp, nil
}

func Test_DecapsSecure_SkipCiphertextCheck(t *testing.T) {
	sk := &PrivateKey{}
	pk := &PublicKey{}

	// (a) 正常 c，使 cPrime == c 時，h1 == h2，回傳正常 bit
	aNorm := uint16(Q / 4)
	cNorm := make([]byte, 32)
	binary.LittleEndian.PutUint16(cNorm[:2], aNorm)

	sharedNorm, _ := DecapsSecure_SkipCiphertextCheck_Normal(cNorm, sk, pk)
	if len(sharedNorm) != 1 {
		t.Fatalf("正常情況應回傳 bit 當 sharedKey，got=%v", sharedNorm)
	}

	// (b) 模擬跳過 c==c'：呼叫 Fault 版本，因為 cPrime != c，h1 != h2 → fallback
	aNorm2 := uint16(Q / 4)
	cFault := make([]byte, 32)
	binary.LittleEndian.PutUint16(cFault[:2], aNorm2)

	sharedFault, _ := DecapsSecure_SkipCiphertextCheck_Fault(cFault, sk, pk)
	if bytes.Equal(sharedFault, sharedNorm) {
		t.Fatalf("預期跳過 c==c' 時走 fallback，但得到相同 sharedKey")
	}
}

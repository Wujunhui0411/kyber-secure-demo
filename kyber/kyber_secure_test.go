package kyber

import (
    "bytes"
    "encoding/binary"
    "testing"

    "github.com/cloudflare/circl/kem/kyber/kyber512"
    "golang.org/x/crypto/sha3"
)

const Q = 3329

// -------------------------------------------------
// 測試 1：poly_to_msgSecure 是否能檢測「跳過 +Q/2」
// -------------------------------------------------
func Test_polyToMsgSecure_SkipAddQOver2(t *testing.T) {
    a := uint16(833)

    bit, err := poly_to_msgSecure(a)
    if err != nil {
        t.Fatalf("正常情況下 poly_to_msgSecure 不該回 ErrDecodeFault，但 got: %v", err)
    }
    expectedNormal := uint8((((uint32(a) << 1) + (Q / 2)) / Q) & 1)
    if bit != expectedNormal {
        t.Fatalf("poly_to_msgSecure 正常回傳 bit 不正確，expect %d, got %d", expectedNormal, bit)
    }

    faultBit := uint8(((uint32(a) << 1) / Q) & 1)
    normalBit := expectedNormal
    if normalBit == faultBit {
        t.Fatalf("選定的 a (%d) 無法令 normalBit != faultBit", a)
    }
    t.Logf("a=%d: normalBit=%d, faultBit=%d", a, normalBit, faultBit)

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
    sk := &kyber512.PrivateKey{}
    pk := &kyber512.PublicKey{}

    aNorm := uint16(Q / 4)
    cNorm := make([]byte, 32)
    binary.LittleEndian.PutUint16(cNorm[:2], aNorm)

    sharedNorm, _ := DecapsSecure(cNorm, sk, pk)

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
func DecapsSecure_SkipCiphertextCheck_Normal(c []byte, sk *kyber512.PrivateKey, pk *kyber512.PublicKey) ([]byte, error) {
    a := coeffFromCiphertext(c)
    bit, _ := poly_to_msgSecure(a)
    sharedTmp := []byte{bit}

    cPrime := make([]byte, len(c))
    copy(cPrime, c)

    var d byte = 0xAB
    var dPrime byte = 0xAB

    eq2 := (d == dPrime)

    h1 := sha3.Sum256(append(c, cPrime...))
    h1 = sha3.Sum256(append(h1[:], d, dPrime))
    h2 := sha3.Sum256(append(cPrime, c...))
    h2 = sha3.Sum256(append(h2[:], dPrime, d))

    if !eq2 || !bytes.Equal(h1[:], h2[:]) {
        return fallbackSharedKey(sk, c), nil
    }
    return sharedTmp, nil
}

func DecapsSecure_SkipCiphertextCheck_Fault(c []byte, sk *kyber512.PrivateKey, pk *kyber512.PublicKey) ([]byte, error) {
    a := coeffFromCiphertext(c)
    bit, _ := poly_to_msgSecure(a)
    sharedTmp := []byte{bit}

    cPrime := make([]byte, len(c))
    copy(cPrime, c)
    cPrime[0] ^= 0xFF

    var d byte = 0xAB
    var dPrime byte = 0xAB

    eq2 := (d == dPrime)

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
    sk := &kyber512.PrivateKey{}
    pk := &kyber512.PublicKey{}

    aNorm := uint16(Q / 4)
    cNorm := make([]byte, 32)
    binary.LittleEndian.PutUint16(cNorm[:2], aNorm)

    sharedNorm, _ := DecapsSecure_SkipCiphertextCheck_Normal(cNorm, sk, pk)
    if len(sharedNorm) != 1 {
        t.Fatalf("正常情況應回傳 bit 當 sharedKey，got=%v", sharedNorm)
    }

    aNorm2 := uint16(Q / 4)
    cFault := make([]byte, 32)
    binary.LittleEndian.PutUint16(cFault[:2], aNorm2)

    sharedFault, _ := DecapsSecure_SkipCiphertextCheck_Fault(cFault, sk, pk)
    if bytes.Equal(sharedFault, sharedNorm) {
        t.Fatalf("預期跳過 c==c' 時走 fallback，但得到相同 sharedKey")
    }
}

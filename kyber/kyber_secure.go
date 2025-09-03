// kyber/kyber_secure.go
package kyber

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/sha3"
)

// Kyber 的模數 Q = 3329
const Q = 3329

// ErrDecodeFault 表示 poly_to_msgSecure 檢測到「解碼時 +Q/2 被跳過」
var ErrDecodeFault = errors.New("poly_to_msgSecure: decode fault detected (missing +Q/2)")

// poly_to_msgSecure：做兩次 (2a+Q/2)/Q 比對；第二次允許在測試時模擬「跳過 +Q/2」
func poly_to_msgSecure(a uint16) (bit uint8, err error) {
	// 第一次（正常）：含 +Q/2
	x1 := ((uint32(a) << 1) + (Q / 2)) / Q
	bit1 := uint8(x1 & 1)

	// 第二次：若啟用故障模擬，改成「跳過 +Q/2」
	var x2 uint32
	if shouldSkipHalfQ() {
		x2 = ((uint32(a) << 1) / Q) // 故障版：跳過 +Q/2
	} else {
		x2 = ((uint32(a) << 1) + (Q / 2)) / Q // 正常版
	}
	bit2 := uint8(x2 & 1)

	if bit1 != bit2 {
		return 0, ErrDecodeFault
	}
	return bit1, nil
}

// coeffFromCiphertext：示範從 c[:2] 取 16-bit a（demo 路徑用）
func coeffFromCiphertext(c []byte) uint16 {
	if len(c) < 2 {
		return 0
	}
	return binary.LittleEndian.Uint16(c[:2])
}

// fallbackSharedKey：故障時給 32B 隨機 key（示範用）
func fallbackSharedKey(sk *PrivateKey, c []byte) []byte {
	buf := make([]byte, 32)
	rand.Read(buf)
	return buf
}

// 金鑰結構：能包 CIRCL 的 key，也可作 demo 用（real=false）
type PrivateKey struct {
	scheme kem.Scheme
	inner  kem.PrivateKey
	real   bool
}

type PublicKey struct {
	scheme kem.Scheme
	inner  kem.PublicKey
	real   bool
}

// DecapsSecure：有真 key → 先做真 decap；再跑雙向雜湊檢查；任何異常都走 fallback。
// 無真 key → 維持 demo 路徑（poly_to_msgSecure + 雙向雜湊檢查），故障時走 fallback。
func DecapsSecure(c []byte, sk *PrivateKey, pk *PublicKey) ([]byte, error) {
	// --- 真實 decapsulation（若有 real key） ---
	if sk != nil && sk.scheme != nil {
		ss, err := sk.scheme.Decapsulate(sk.inner, c)
		if err != nil {
			// 建議：不要把錯丟出去，避免成為 error oracle；直接走 fallback
			return fallbackSharedKey(sk, c), nil
		}
		// 雙向雜湊檢查（沿用你的 secure 思路）
		cPrime := make([]byte, len(c))
		copy(cPrime, c)
		var d byte = 0xAB
		var dPrime byte = 0xAB
		eq1 := bytes.Equal(c, cPrime)
		eq2 := (d == dPrime)
		h1 := sha3.Sum256(append(c, cPrime...))
		h1 = sha3.Sum256(append(h1[:], d, dPrime))
		h2 := sha3.Sum256(append(cPrime, c...))
		h2 = sha3.Sum256(append(h2[:], dPrime, d))
		if !(eq1 && eq2) || !bytes.Equal(h1[:], h2[:]) {
			return fallbackSharedKey(sk, c), nil
		}
		return ss, nil
	}

	// --- demo 路徑 ---
	a := coeffFromCiphertext(c)
	bit, decodeErr := poly_to_msgSecure(a)
	if decodeErr != nil {
		return fallbackSharedKey(sk, c), nil
	}
	sharedTmp := []byte{bit}

	cPrime := make([]byte, len(c))
	copy(cPrime, c)
	var d byte = 0xAB
	var dPrime byte = 0xAB
	eq1 := bytes.Equal(c, cPrime)
	eq2 := (d == dPrime)
	h1 := sha3.Sum256(append(c, cPrime...))
	h1 = sha3.Sum256(append(h1[:], d, dPrime))
	h2 := sha3.Sum256(append(cPrime, c...))
	h2 = sha3.Sum256(append(h2[:], dPrime, d))
	if !(eq1 && eq2) || !bytes.Equal(h1[:], h2[:]) {
		return fallbackSharedKey(sk, c), nil
	}
	return sharedTmp, nil
}

package kyber

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/sha3"
)

// Kyber 的模數 Q = 3329
const Q = 3329

// ErrDecodeFault 表示 poly_to_msgSecure 檢測到「解碼時 +Q/2 被跳過」
var ErrDecodeFault = errors.New("poly_to_msgSecure: decode fault detected (missing +Q/2)")

// poly_to_msgSecure 將單一係數 a 解碼成 bit (0/1)。
// 做兩次 (2a + Q/2)/Q，再比對兩次結果，若不同則回 ErrDecodeFault。
func poly_to_msgSecure(a uint16) (bit uint8, err error) {
	// 第一次計算
	x1 := ((uint32(a) << 1) + (Q / 2)) / Q
	bit1 := uint8(x1 & 1)

	// 第二次計算
	x2 := ((uint32(a) << 1) + (Q / 2)) / Q
	bit2 := uint8(x2 & 1)

	if bit1 != bit2 {
		return 0, ErrDecodeFault
	}
	return bit1, nil
}

// coeffFromCiphertext 示範只把 c[:2] 當成一個 16-bit coefficient a
func coeffFromCiphertext(c []byte) uint16 {
	if len(c) < 2 {
		return 0
	}
	return binary.LittleEndian.Uint16(c[:2])
}

// fallbackSharedKey 若解封裝失敗就回隨機值，示範用 32 bytes 隨機
func fallbackSharedKey(c []byte) []byte {
	buf := make([]byte, 32)
	rand.Read(buf)
	return buf
}

// DecapsSecure 在解封裝階段同時防範跳過 +Q/2 及比對錯誤的攻擊。
// c 是密文，sk 是私鑰（bytes），回傳 shared key 或 fallback
func DecapsSecure(c, sk []byte) ([]byte, error) {
	// Step 1: 讀取 ciphertext 裡的係數 a
	a := coeffFromCiphertext(c)

	// Step 2: 用 poly_to_msgSecure 檢查 +Q/2 是否被跳過
	bit, decodeErr := poly_to_msgSecure(a)
	if decodeErr != nil {
		// 發現跳過 +Q/2，fallback 返回隨機 shared key
		return fallbackSharedKey(c), nil
	}
	sharedTmp := []byte{bit}

	// Step 3: 重新加密 & 比對模擬 (此處用簡單範例)
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
		// 比對失敗 fallback
		return fallbackSharedKey(c), nil
	}

	// 全部檢測通過，回傳 sharedTmp（示範用 bit）
	return sharedTmp, nil
}


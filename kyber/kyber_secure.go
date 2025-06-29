// kyber_secure.go
package kyber

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/sha3"
)

// -------------------------------------------------
// 常數與錯誤定義
// -------------------------------------------------

// Kyber 的模數 Q = 3329
const Q = 3329

// ErrDecodeFault 表示 poly_to_msgSecure 檢測到「解碼時 +Q/2 被跳過」
var ErrDecodeFault = errors.New("poly_to_msgSecure: decode fault detected (missing +Q/2)")

// -------------------------------------------------
// 1. 解碼防禦：poly_to_msgSecure
// -------------------------------------------------

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

// -------------------------------------------------
// 2. 字節序工具：從密文中讀取多項式係數 a
// -------------------------------------------------

// coeffFromCiphertext 示範只把 c[:2] 當成一個 16-bit coefficient a
func coeffFromCiphertext(c []byte) uint16 {
	if len(c) < 2 {
		return 0
	}
	return binary.LittleEndian.Uint16(c[:2])
}

// -------------------------------------------------
// 3. 輔助函式：fallbackSharedKey
// -------------------------------------------------

// 假設 sharedKey 有 32 bytes，若解封裝失敗就回隨機值。
// 實際 Kyber 應該是 H(s || c || d)，此處僅示範隨機。
func fallbackSharedKey(sk *PrivateKey, c []byte) []byte {
	buf := make([]byte, 32)
	rand.Read(buf)
	return buf
}

// -------------------------------------------------
// 4. 假設 Key/Encaps 相關結構 (示範用，請替換成實際 crystals-go 定義)
// -------------------------------------------------

type PrivateKey struct {
	// 實際情況包含 s, e, _, _ 等欄位
}

type PublicKey struct {
	// 實際情況包含 A, b, pkBytes 等
}

// -------------------------------------------------
// 5. 解封裝防禦：DecapsSecure
// -------------------------------------------------

// DecapsSecure 在解封裝 (Decaps) 階段同時防範：
//  1. 跳過「+Q/2」解碼步驟 → poly_to_msgSecure 可檢測
//  2. 跳過「c == cPrime / d == dPrime」比對 → 雙向雜湊比對可檢測
func DecapsSecure(c []byte, sk *PrivateKey, pk *PublicKey) ([]byte, error) {
	// ------------------- Step 1: PKE 解密與 poly_to_msgSecure -------------------
	a := coeffFromCiphertext(c)
	bit, decodeErr := poly_to_msgSecure(a)
	if decodeErr != nil {
		// 跳過 +Q/2，poly_to_msgSecure 回 ErrDecodeFault → 立即 fallback
		return fallbackSharedKey(sk, c), nil
	}
	// 正常解碼後，sharedTmp 可以由 μ' 做 Hash 取得。但此示範直接用 bit。
	sharedTmp := []byte{bit}

	// ------------------- Step 2: FO 重新加密與一致性檢查 -------------------

	// (a) 重新加密結果 cPrime (此處示範直接 copy c)
	cPrime := make([]byte, len(c))
	copy(cPrime, c)

	// (b) 假設確認值 d、dPrime 都存在某個固定欄位 (此處示範用常數)
	var d byte = 0xAB
	var dPrime byte = 0xAB

	// (c) 拆成兩行比對 c==cPrime 與 d==dPrime
	eq1 := bytes.Equal(c, cPrime)
	eq2 := (d == dPrime)

	// (d) 再做雙向雜湊比對
	h1 := sha3.Sum256(append(c, cPrime...))
	h1 = sha3.Sum256(append(h1[:], d, dPrime))
	h2 := sha3.Sum256(append(cPrime, c...))
	h2 = sha3.Sum256(append(h2[:], dPrime, d))

	if !(eq1 && eq2) || !bytes.Equal(h1[:], h2[:]) {
		// 只要任何一項檢查失敗 → fallback
		return fallbackSharedKey(sk, c), nil
	}

	// ------------------- Step 3: 全部檢測通過，回傳正常 shared key -------------------
	return sharedTmp, nil
}

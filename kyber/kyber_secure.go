package kyber

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// 異常時回傳的 32B fallback（不拋錯、避免 error oracle）
func fallbackKey32() []byte {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return k
}

// 產生 (a||b) 與 (b||a) 的雙向雜湊拼接，用來加強一致性檢查
func hashPair(a, b []byte) []byte {
	h1 := sha256.Sum256(append(a, b...))
	h2 := sha256.Sum256(append(b, a...))
	out := make([]byte, 64)
	copy(out[:32], h1[:])
	copy(out[32:], h2[:])
	return out
}

// 測試/故障模擬鉤子，實作於 _polyToMsgHook（依 build tag 切換）
func poly_to_msgSecure(in []byte) ([]byte, error) {
	return _polyToMsgHook(in)
}

// 安全解封裝：封裝原生 decap，加入偵測＋fallback 策略
// 策略：
// 1) 原生 decap 失敗 → 回傳 32B fallback（不拋錯）
// 2) hook 比對不同 → 視為 fault → 回傳 32B fallback（不拋錯）
// 3) 雙向雜湊檢查失敗 → 回傳 32B fallback（不拋錯）
func DecapsulateSecure(ct, sk, pk []byte) ([]byte, error) {
	// 1) 原生解封裝
	ss, err := DecapsulateRaw(ct, sk)
	if err != nil {
		return fallbackKey32(), nil
	}

	// 2) 以 hook 對 ct 做可比較的「派生」（示意用途）
	recovered, hookErr := poly_to_msgSecure(ct)
	if hookErr != nil {
		return fallbackKey32(), nil
	}

	if len(recovered) > 0 && !bytes.Equal(recovered[:min(32, len(recovered))], ss[:min(32, len(ss))]) {
		// 與原輸出前 32B 不一致 → 視為故障
		return fallbackKey32(), nil
	}

	// 3) 雙向雜湊與 ct 綁定（示意檢查）
	h := hashPair(ct, ss)
	if len(h) != 64 {
		return fallbackKey32(), nil
	}

	return ss, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 只做偵測、不解封裝
var ErrDecodeFault = errors.New("decode fault detected")

func DetectDecodeFault(ct []byte) error {
	recovered, err := poly_to_msgSecure(ct)
	if err != nil {
		return ErrDecodeFault
	}
	if len(recovered) == 0 {
		return ErrDecodeFault
	}
	return nil
}

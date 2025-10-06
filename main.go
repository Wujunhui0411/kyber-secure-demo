// main.go
package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"flag"
	"fmt"
	"time"

	"github.com/Wujunhui0411/kyber-secure-demo/kyber"
)

func main() {
	level := flag.Int("level", 1024, "Kyber 安全等級: 512 / 768 / 1024")
	secure := flag.Bool("secure", true, "是否使用 Secure 解封裝")
	rounds := flag.Int("rounds", 10000, "重複執行次數（用於取平均）")
	flag.Parse()

	fmt.Printf("執行 Kyber KEM（KeyGen → Encapsulate → Decapsulate），rounds=%d\n", *rounds)
	fmt.Printf("安全等級: Kyber%d\n", *level)
	fmt.Printf("是否使用 Secure 解封裝: %v\n", *secure)

	// 1) 產生真實金鑰
	pk, sk, err := kyber.KeyGen(*level)
	if err != nil {
		fmt.Printf("金鑰產生失敗: %v\n", err)
		return
	}

	// 2) 預熱（避免第一次呼叫的初始化成本影響統計）
	if err := warmup(pk, sk, *secure); err != nil {
		fmt.Printf("預熱失敗: %v\n", err)
		return
	}

	var totalDec time.Duration
	var lastCT, lastEnc, lastDec []byte
	var matches, mismatches int

	startAll := time.Now()
	for i := 0; i < *rounds; i++ {
		// 3) 封裝（sender 端）
		ct, ssEnc, err := kyber.Encapsulate(pk)
		if err != nil {
			fmt.Printf("第 %d 次封裝失敗: %v\n", i+1, err)
			return
		}

		// 4) 解封裝（receiver 端），量測耗時
		t0 := time.Now()
		ssDec, err := kyber.DecapsulateExt(ct, sk, pk, *secure)
		if err != nil {
			fmt.Printf("第 %d 次解封裝失敗: %v\n", i+1, err)
			return
		}
		totalDec += time.Since(t0)

		// 5) 驗證 shared key 一致（constant-time）
		if constTimeEqual(ssEnc, ssDec) {
			matches++
		} else {
			mismatches++
		}

		lastCT, lastEnc, lastDec = ct, ssEnc, ssDec
	}
	totalAll := time.Since(startAll)

	avg := totalDec.Nanoseconds() / int64(*rounds)
	fmt.Println("全部完成")
	fmt.Printf("總耗時（含封裝等開銷）: %v\n", totalAll)
	fmt.Printf("僅解封裝總耗時: %v（平均每次: %d ns）\n", totalDec, avg)
	fmt.Printf("最後一次 Ciphertext 大小: %d bytes\n", len(lastCT))
	fmt.Printf("Shared key 一致次數: %d / %d（不一致: %d）\n", matches, *rounds, mismatches)
	fmt.Printf("最後一次 Shared key (enc==dec): %v\n", bytes.Equal(lastEnc, lastDec))
	fmt.Printf("Shared key (hex，前 32B): %s\n", hexHead(lastEnc, 32))

	if mismatches > 0 && *secure {
		fmt.Println("注意：使用 Secure 模式且在故障情境（例如以 -tags fault 執行）時，偵測到異常會回傳隨機 fallback key，導致不一致屬預期行為。")
	}
}

// 預熱：跑一輪完整流程，避免初始化雜訊
func warmup(pk, sk []byte, secure bool) error {
	ct, ssEnc, err := kyber.Encapsulate(pk)
	if err != nil {
		return err
	}
	ssDec, err := kyber.DecapsulateExt(ct, sk, pk, secure)
	if err != nil {
		return err
	}
	if !constTimeEqual(ssEnc, ssDec) && !secure {
		// 非 secure 模式下若不一致代表異常；secure 模式下不一致可能是故障偵測 fallback。
		return fmt.Errorf("warmup shared key mismatch")
	}
	return nil
}

// 常數時間比較，避免時序側信道
func constTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// 只印出前 n bytes 的 hex，避免輸出過長
func hexHead(b []byte, n int) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) > n {
		return hex.EncodeToString(b[:n]) + "..."
	}
	return hex.EncodeToString(b)
}

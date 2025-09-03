# kyber-secure-demo

Secure **Kyber KEM** demo in Go — with **CLI**, **tests**, **fault-injection hardening**, and **benchmarks**.

> 本專案示範如何在 Go 中使用 **Cloudflare CIRCL** 的 Kyber（512/768/1024），並加入 **故障注入防禦**（偵測 + fallback）。
> 另提供以 **build tag** 觸發的「**軟體故障模擬**」機制，方便在測試環境重現「跳過 `+Q/2`」的情境。

---

## 目錄

* [專案架構](#專案架構)
* [特色與功能](#特色與功能)
* [安裝與相依性](#安裝與相依性)
* [快速開始（CLI）](#快速開始cli)
* [測試（一般 / 故障模擬）](#測試一般--故障模擬)
* [Build Tags 說明](#build-tags-說明)
* [Benchmark](#benchmark)
* [安全模型（威脅與防護）](#安全模型威脅與防護)
* [指令速查](#指令速查)

---

## 專案架構

```
kyber-secure-demo/
├── go.mod
├── main.go
└── kyber/
    ├── kem.go                  # 使用 Cloudflare CIRCL 實作 KeyGen / Encapsulate / Decapsulate（真實 KEM）
    ├── kyber_secure.go         # Secure 解封裝 + 故障偵測與 fallback（含教學用 demo 路徑）
    ├── decaps_secure_ext.go    # 統一入口：DecapsulateExt(secure/original)
    ├── fault_hooks_off.go      # 預設：不啟用故障注入（無 build tag 時編譯）
    ├── fault_hooks.go          # 只在 -tags fault 編譯，提供「跳過 +Q/2」的軟體故障模擬開關
    ├── kyber_secure_test.go    # 通用測試（不依賴 fault tag）
    ├── fault_test.go           # 只在 -tags fault 編譯的故障模擬測試
    ├── secure_kem_test.go      # 真實 KEM 路徑的負向測試（破壞 ciphertext → fallback）
    └── bench_test.go           # benchmark（比較 secure / original）
```

---

## 特色與功能

### 真實 Kyber KEM（CIRCL）

* 介面：`KeyGen(level)`, `Encapsulate(pk)`, `DecapsulateRaw(ct, sk)`
* 等級：`512 | 768 | 1024`

### Secure 解封裝（安全模式）

* 入口：`DecapsulateSecure(ct, sk, pk)`（或使用 `DecapsulateExt(..., secure=true)`）
* 異常（解碼故障 / 雜湊不一致 / 原生 decap 出錯）時：

  * **不報錯**（避免 error oracle）
  * **回傳 32B fallback key**（亂數），由上層協議自行驗證失敗

### 故障偵測（demo 路徑）

* 函式：`poly_to_msgSecure(a)`
* 目的：模擬攻擊者在「係數→位元」轉換時**跳過 `+Q/2`**（常見的 Fault Injection 點）
* 設計：內部做兩次運算；在 **fault 模式** 下第二次改為「不加 `+Q/2`」，若兩次結果不同 → `ErrDecodeFault`

### 雙向雜湊一致性

* 比對 `hash(c‖c')` 與 `hash(c'‖c)`，避免只改寫單向比對就繞過檢查

---

## 安裝與相依性

* Go 1.20+（建議 1.21+）
* 相依：

  * `github.com/cloudflare/circl`（Kyber KEM）
  * `golang.org/x/crypto`（SHA3 等）

```bash
go mod tidy
# 如需指定 CIRCL 版本：
# go get github.com/cloudflare/circl@latest && go mod tidy
```

---

## 安裝與引用（Import）

**安裝套件**（建議固定版本標籤）：

```bash
# 抓最新版
go get github.com/Wujunhui0411/kyber-secure-demo@latest
# 或抓特定版本（例如 v0.1.0）
# go get github.com/Wujunhui0411/kyber-secure-demo@v0.1.0
```

**匯入路徑**（與 go.mod 的 module 路徑一致）：

```go
import "github.com/Wujunhui0411/kyber-secure-demo/kyber"
```

**最小使用範例**：

```go
package main

import (
    "fmt"
    "log"

    "github.com/Wujunhui0411/kyber-secure-demo/kyber"
)

func main() {
    // 1) 產生金鑰（Kyber1024）
    pk, sk, err := kyber.KeyGen(1024)
    if err != nil { log.Fatal(err) }

    // 2) 封裝（sender）
    ct, ssEnc, err := kyber.Encapsulate(pk)
    if err != nil { log.Fatal(err) }

    // 3) 安全解封裝（receiver）
    ssDec, err := kyber.DecapsulateSecure(ct, sk, pk)
    if err != nil { log.Fatal(err) }

    fmt.Println("ciphertext bytes:", len(ct))
    fmt.Println("shared key match:", string(ssEnc) == string(ssDec))
}
```

> 備註：`DecapsulateSecure` 會在偵測到異常時**不報錯**，改回 **32B fallback key**；上層協議（AEAD/KDF/AEAD）應據此驗證是否有效。

---

## 快速開始（CLI）

主程式：`main.go`

```bash
# Kyber1024、開啟 Secure、重複 10000 次
go run main.go --level=1024 --secure=true --rounds=10000

# Kyber768、關閉 Secure、重複 5000 次
go run main.go --level=768 --secure=false --rounds=5000
```

**參數**

* `--level`：`512 | 768 | 1024`
* `--secure`：`true | false`
* `--rounds`：重複次數（取平均耗時）

**輸出包含**

* 總耗時（含封裝）
* 解封裝總耗時與平均（ns）
* 最後一次 ciphertext 大小
* shared key 一致性（Encaps vs Decaps）

---

## 測試（一般 / 故障模擬）

### 一般模式（不含故障注入）

```bash
go test ./kyber -v
```

重點（名稱以實際檔案為準）：

* `TestDecapsulateExt_SecureVsOriginal`：合法密文下，`secure=true/false` 結果一致
* `TestDecap_Secure_FallbackOnCorruptedCiphertext_Real`：**真實 KEM** 路徑翻 bit 破壞密文 → `secure=true` **不拋錯** 且回 **fallback key（32B）**

### 故障模擬模式（僅在帶 `-tags fault` 時編譯）

```bash
go test -tags fault ./kyber -v
```

會執行：

* `TestPolyToMsgSecure_FaultDetected`：指定 `a=833` 並**跳過 `+Q/2`** → 期望 `ErrDecodeFault`
* `TestDecapsSecure_FallbackOnFault_Demo`：demo 路徑

  * 正常：`a=Q/4` → 1B bit
  * 故障：`a=833` + 跳過 `+Q/2` → **fallback key（32B）**，且 ≠ 正常輸出
* 其他（如 `Test_DecapsSecure_SkipDecodeFault` / `Test_DecapsSecure_SkipCiphertextCheck`）：偵測異常皆**不報錯**、改走 fallback

---

## Build Tags 說明

* `fault_hooks_off.go`：`//go:build !fault`（**預設**，故障模擬關閉）
* `fault_hooks.go`：`//go:build fault`（**僅**在 `-tags fault` 編譯，提供 `Enable/Disable` 開關）
* `fault_test.go`：檔頭含 `//go:build fault`，避免在一般模式造成預期外 FAIL

**指令**

```bash
# 一般測試（不含故障）
go test ./kyber -v

# 故障模擬測試（啟用跳過 +Q/2）
go test -tags fault ./kyber -v
```

---

## Benchmark

比較 secure / original 在 **解封裝** 的效能差異（名稱以專案內為準）：

```bash
go test -bench=BenchmarkDecap_ -benchmem ./kyber
# 或
go test -bench=BenchmarkDecapsSecure -benchmem ./kyber
```

---

## 安全模型（威脅與防護）

**攻擊面：**
針對 **硬體層故障注入**（Fault Injection on Decapsulation），例如在「係數→位元」的四捨五入流程中**跳過 `+Q/2`**。攻擊者可藉由「正確 vs 錯誤輸出」差異蒐集訊號，以推測私鑰（fault/error oracle）。

**我們的防護：**

1. `poly_to_msgSecure`（demo 路徑）能偵測「跳過 `+Q/2`」異常（測試用 build tag 可注入）
2. **雙向雜湊**檢查 ciphertext 一致性，避免單向比對被繞過
3. **fallback key**：偵測到異常時**不報錯**、回 32B 隨機金鑰；上層協議（AEAD/KDF）自然驗證失敗，但不暴露內部細節

**真實 KEM 路徑（CIRCL）：**
無法直接在函式庫內「跳過 `+Q/2`」，因此以**破壞 ciphertext** 誘發異常，驗證 `secure=true` 的韌性（不報錯 → fallback）。

---

## 指令速查

```bash
# 安裝相依
go mod tidy

# 一般單元測試（不含故障）
go test ./kyber -v

# 啟用「跳過 +Q/2」的軟體故障模擬測試
go test -tags fault ./kyber -v

# Benchmark
go test -bench=BenchmarkDecap_ -benchmem ./kyber

# CLI：Kyber1024、Secure=true、重複 10000 次
go run main.go --level=1024 --secure=true --rounds=10000
```

---

> 本專案僅供教學與研究用途。請依各相依套件之授權條款使用。
> Kyber KEM 實作取自 Cloudflare **CIRCL**：`github.com/cloudflare/circl`。

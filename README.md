# kyber-secure-demo

Secure **Kyber KEM** demo in Go — with **CLI**, **tests**, **fault-injection hardening**, and **benchmarks**.

> 本專案示範如何在 Go 中使用 **Cloudflare CIRCL** 的 Kyber（512/768/1024），並加入 **故障注入防禦**（偵測 + fallback）。  
> 另提供以 **build tag** 觸發的「**軟體故障模擬**」機制，方便在測試環境重現「跳過 `+Q/2`」的情境。

---

## 目錄

* [專案架構](#專案架構)  
* [特色與功能](#特色與功能)  
* [新增 API（重點）](#新增-api重點)  
* [安裝與相依性](#安裝與相依性)  
* [快速開始（CLI）](#快速開始cli)  
* [在其他專案中使用（Import）](#在其他專案中使用import)  
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
├── go.sum
├── README.md
├── main.go
└── kyber/
    ├── kem.go                  # KeyGen / Encapsulate / DecapsulateRaw (CIRCL)
    ├── kyber_secure.go         # DecapsulateSecure + DetectDecodeFault + hooks
    ├── decaps_secure_ext.go    # DecapsulateExt (secure switch)
    ├── fault_hooks_off.go      # 預設：不啟用故障注入
    ├── fault_hooks.go          # -tags fault 時啟用軟體故障模擬
    ├── kyber_secure_test.go    # 單元測試（一般）
    ├── fault_test.go           # 只在 -tags fault 時執行的測試
    ├── secure_kem_test.go      # 針對真實 KEM 路徑的測試
    └── bench_test.go           # benchmark
```

---

## 特色與功能

### 真實 Kyber KEM（CIRCL）
* 介面：`KeyGen(level)`, `Encapsulate(pk)`, `DecapsulateRaw(ct, sk)`  
* 支援等級：`512 | 768 | 1024`

### Secure 解封裝（安全模式）
* 入口：`DecapsulateSecure(ct, sk, pk)`（或 `DecapsulateExt(ct, sk, pk, secure=true)`）  
* 行為：  
  * 當偵測到異常（解封裝錯誤 / 故障 / 雜湊不一致）時，**不回傳 error**。  
  * 改回傳 **32 bytes 的隨機 fallback key**（避免 error oracle / side-channel）。  
  * 上層 AEAD/KDF 可自行驗證失敗並丟棄。

### 故障偵測（demo / 測試用）
* `poly_to_msgSecure`：示範/測試用的偵測鉤子（實際 fault 模擬由 `-tags fault` 控制）。  
* 使用雙向雜湊一致性（`hash(c||s)` vs `hash(s||c)`）作為額外檢查，降低單向繞過風險。

---

## 新增 API（重點）

### 對外函式範例
```go
// 產生 keypair（level: 512 | 768 | 1024）
pk, sk, err := kyber.KeyGen(level)

// 封裝（給 public key bytes）
ct, ssEnc, err := kyber.Encapsulate(pk)

// 原始解封裝（會回傳 error）
ssDec, err := kyber.DecapsulateRaw(ct, sk)

// 安全解封裝（不報錯；異常回 32B fallback 隨機值）
ssDec, err := kyber.DecapsulateSecure(ct, sk, pk)

// 統一入口：secure 開關（true -> secure path；false -> raw）
ssDec, err := kyber.DecapsulateExt(ct, sk, pk, secure)

// 僅偵測（不解封裝）；若偵測到 fault 則回 ErrDecodeFault
err := kyber.DetectDecodeFault(ct)
```

**說明**：  
* `DecapsulateSecure` 在偵測到任何可疑情況時回傳隨機 fallback（32 bytes），避免將錯誤原因透露給攻擊者。  
* `DecapsulateExt` 是方便的切換入口，適合 benchmark / 比較用途。  
* 若上層需要直接判斷「真實錯誤 vs fallback」，使用 `DecapsulateRaw`（會回 error）或用 `DetectDecodeFault` 作額外檢查。

---

## 安裝與相依性

* 建議 Go 版本：1.20+（你的 repo 使用 `go 1.22.0` / `toolchain go1.22.3` 也可）  
* 主要相依：  
  * `github.com/cloudflare/circl v1.6.1`  
  * `golang.org/x/crypto v0.22.0`

```bash
go mod tidy
# 若想指定版本
# go get github.com/cloudflare/circl@v1.6.1 && go mod tidy
```

---

## 快速開始（CLI）

主程式：`main.go`（已提供範例）

```bash
# Kyber1024，啟用 Secure，執行 10000 回合
go run main.go --level=1024 --secure=true --rounds=10000

# Kyber768，關閉 Secure 模式
go run main.go --level=768 --secure=false --rounds=5000
```

**CLI 參數**  
* `--level`：`512 | 768 | 1024`  
* `--secure`：`true | false`（決定 `DecapsulateExt` 的路徑）  
* `--rounds`：重複次數（取平均）

**CLI 輸出範例**
```
執行 Kyber KEM（KeyGen → Encapsulate → Decapsulate），rounds=10000
安全等級: Kyber1024
是否使用 Secure 解封裝: true
全部完成
總耗時（含封裝等開銷）: 2.31s
僅解封裝總耗時: 1.84s（平均每次: 184000 ns）
Shared key 一致次數: 10000 / 10000（不一致: 0）
Shared key (hex 前 32B): 4a9d23e8...
```

---

## 在其他專案中使用（Import）

```bash
go get github.com/Wujunhui0411/kyber-secure-demo@latest
```

```go
import "github.com/Wujunhui0411/kyber-secure-demo/kyber"

pk, sk, _ := kyber.KeyGen(1024)
ct, ssEnc, _ := kyber.Encapsulate(pk)
ssDec, _ := kyber.DecapsulateSecure(ct, sk, pk)
fmt.Println(bytes.Equal(ssEnc, ssDec)) // true 表示安全無故障
```

**備註**：`DecapsulateSecure` 偵測到異常時不會回傳錯誤；若需原始錯誤語意請使用 `DecapsulateRaw`。

---

## 測試（一般 / 故障模擬）

### 一般模式（預設無 fault）
```bash
go test ./kyber -v
```

### 故障模擬（使用 build tag）
啟用軟體故障模擬（`-tags fault`），可模擬例如「跳過 `+Q/2`」等錯誤：
```bash
go test -tags fault ./kyber -v
```

測試會包含：
* `TestDecapsulateExt_SecureVsOriginal`（合法密文下 secure=true/false 一致）  
* `TestPolyToMsgSecure_FaultDetected`（fault 模式下偵測成功）  
* `TestDecapsSecure_FallbackOnFault_Demo`（demo 路徑下偵測並 fallback）

---

## Build Tags 說明

| 檔案 | Build Tag | 說明 |
|------|-----------|------|
| `fault_hooks_off.go` | `!fault` | 預設（不模擬故障） |
| `fault_hooks.go`     | `fault`  | 模擬跳過 `+Q/2` 的故障（bit flip） |
| `fault_test.go`      | `fault`  | 僅在 fault 模式下執行的測試 |

**指令範例**
```bash
# 一般測試
go test ./kyber -v

# 啟用 fault 模擬的測試
go test -tags fault ./kyber -v
```

---

## Benchmark

比較 secure / original 在解封裝的效能差異：
```bash
go test -bench=BenchmarkDecap_ -benchmem ./kyber
# 或
go test -bench=BenchmarkDecapsSecure -benchmem ./kyber
```

---

## 安全模型（威脅與防護）

**威脅**：硬體層 Fault Injection（例如在係數→位元四捨五入時跳過 `+Q/2`），攻擊者可藉由「正確 vs 錯誤輸出」區分進行側通道或密鑰回復攻擊。

**防護**：
1. `poly_to_msgSecure` + `-tags fault` 用於模擬並驗證偵測機制。  
2. 雙向雜湊一致性檢查（綁定 ciphertext 與 shared secret）。  
3. 發現異常時回傳 32-byte 隨機 fallback key，避免 error oracle。

**真實 KEM（CIRCL）注意**：CIRCL 的內部實作不會被我們在 library 層直接改寫；我們以破壞 ciphertext 或 fault hook（測試）來驗證 `DecapsulateSecure` 的防護效果。

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

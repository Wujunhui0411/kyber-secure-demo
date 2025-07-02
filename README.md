# kyber-secure-demo
Secure Kyber demo in Go with CLI and Benchmark

#專案架構  

kyber-secure-demo/  

├── go.mod  

├── main.go  

├── kyber/  

│   ├── kyber_secure.go  

│   ├── kyber_secure_test.go  

│   ├── decaps_secure_ext.go         // 包裝 crystals-go 的 secure 解封裝  

│   ├── decaps_secure_ext_test.go    // 相關測試  

│   └── bench_test.go                // benchmark 測試


## 專案介紹

本專案基於 [crystals-go](https://github.com/kudelskisecurity/crystals-go) 套件，實作並展示了 Kyber 密碼學演算法在 Go 語言環境中的應用，支援 Kyber512、Kyber768 及 Kyber1024 三種安全等級。

主要功能包含：

- 金鑰產生 (KeyGen)
- 封裝 (Encapsulation)
- 解封裝 (Decapsulation)，同時支援原始版本與新增的 Secure 解封裝機制
- CLI 工具：可選擇不同安全等級與是否使用 Secure 解封裝，並測量執行時間
- Benchmark 測試：評估 Secure 解封裝與普通解封裝在不同安全等級下的效能差異

## 程式功能說明

本專案中的 Secure 解封裝實作，除了執行標準的解密流程外，特別加入了兩個針對故障攻擊的防護檢查機制，以確保在發生異常計算時能夠走 fallback 流程，進而生成不同的 shared key，防止攻擊者透過旁路修改的方式取得正確結果。以下說明主要測試模組的功能：

### 1. `poly_to_msgSecure` 的故障檢測機制

- **目的**：驗證在將多項式係數轉換成比特資訊時，若攻擊者跳過「加上 Q/2」這一步驟（簡稱跳過 `+Q/2`），會導致最終 bit 值改變。
- **設計**：
  - 選定特定係數值 `a`（例如 a = 833），確保：
    - 正常情況下：`bit = (((2*a + Q/2) / Q) & 1)` 得到期望結果。
    - 若跳過 `+Q/2`，計算變成 `bit = ((2*a) / Q) & 1`，結果與正常情況不同。
- **測試結果**：
  - 當正常計算與故障計算結果不同時，`poly_to_msgSecure` 能成功偵測異常並回傳錯誤 (`ErrDecodeFault`)。

### 2. `DecapsSecure` 的 Fault Fallback 機制

- **目的**：檢查當 Secure 解封裝過程中因跳過 `+Q/2` 而被偵測到錯誤時，是否能透過 fallback 機制生成不同於正常解封裝的 shared key。
- **設計**：
  - 構造兩種情境：
    1. **正常情況**：ciphertext 中包含的係數為 `a = Q/4`，不會觸發錯誤，產生正常 shared key。
    2. **故障情況**：ciphertext 中包含的係數為 `a = 833`，觸發 `poly_to_msgSecure` 的錯誤，進而進入 fallback 流程，產生另一個 shared key。
- **測試結果**：
  - 當兩種情況下的 shared key 不相同時，表示 fallback 機制正確運作，有效防止故障注入攻擊。

### 3. Ciphertext 雙向雜湊檢查

- **目的**：在解封裝過程中，除了直接比對原始 ciphertext (`c`) 與重新加密結果 (`cPrime`)，還額外利用雙向雜湊（bi-directional hash）來保護過程，防止攻擊者跳過 ciphertext 比對檢查。
- **設計**：
  - **正常情況**：模擬跳過直接比對，但令 `cPrime == c`，此時雜湊比對 `hash(c||c') == hash(c'||c)`，返回正常 shared key。
  - **故障情況**：模擬 `cPrime ≠ c`，則雙向雜湊比對失敗，觸發 fallback 流程。
- **測試結果**：
  - 驗證當 `cPrime` 被修改時，雙向雜湊能成功偵測異常並啟動 fallback，有效提升整體安全性。


## 如何執行

### 1. 下載相依套件
go mod tidy  

### 2. 單元測試
go test ./kyber

### 3. 執行Benchmark測試
go test -bench=BenchmarkDecapsSecure ./kyber

### 4. 執行主程式
go run main.go --level=安全等級 --secure=true  
(安全等級可為512/768/1024)

go run main.go --level=安全等級 --secure=false  
(安全等級可為512/768/1024)

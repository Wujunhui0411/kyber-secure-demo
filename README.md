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

│   └── decaps_secure_ext_test.go    // 相關測試  

└── bench_test.go                    // benchmark 測試


## 專案介紹

本專案基於 [crystals-go](https://github.com/kudelskisecurity/crystals-go) 套件，實作並展示了 Kyber 密碼學演算法在 Go 語言環境中的應用，支援 Kyber512、Kyber768 及 Kyber1024 三種安全等級。

主要功能包含：

- 金鑰產生 (KeyGen)
- 封裝 (Encapsulation)
- 解封裝 (Decapsulation)，同時支援原始版本與新增的 Secure 解封裝機制
- CLI 工具：可選擇不同安全等級與是否使用 Secure 解封裝，並測量執行時間
- Benchmark 測試：評估 Secure 解封裝與普通解封裝在不同安全等級下的效能差異

## 新增功能與測試

- **decaps_secure_ext.go / decaps_secure_ext_test.go**  
  封裝了一套 Secure Decapsulation 擴充功能，用於增強對故障攻擊與注入攻擊的防護。  
  對應的測試確保 Secure Decapsulation 的正確性與與原始解封結果一致。

- **bench_test.go**  
  針對 Kyber512、768、1024 三個安全等級，實作有無 Secure 解封裝的效能基準測試。  
  可用以量化安全防護對效能的影響，為後續優化提供依據。

## 如何執行

### 1. 下載相依套件
go mod tidy

### 2.執行主程式CLI
go run main.go --level=768 --secure=true
--level 可設定為 512、768 或 1024
--secure 設為 true 使用 Secure 解封裝，false 使用普通解封裝

### 3. 執行單元測試
go test ./kyber

### 4. 執行Benchmark測試
go test -bench=. -benchmem

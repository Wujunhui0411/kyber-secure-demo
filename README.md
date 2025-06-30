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

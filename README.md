# kyber-secure-demo
Secure Kyber demo in Go with CLI and Benchmark

專案架構
kyber-secure-demo/
├── go.mod
├── main.go
├── kyber/
│   ├── kyber_secure.go
│   ├── kyber_secure_test.go
│   ├── decaps_secure_ext.go         // 包裝 crystals-go 的 secure 解封裝
│   └── decaps_secure_ext_test.go    // 相關測試
└── bench_test.go                    // benchmark 測試

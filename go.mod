module github.com/Wujunhui0411/kyber-secure-demo

go 1.22.0

toolchain go1.22.3

require (
	github.com/cloudflare/circl v1.6.1
	golang.org/x/crypto v0.22.0 // 確保 sha3 用得上
)

require golang.org/x/sys v0.19.0 // indirect

package main

import (
	"flag"
	"fmt"
	"time"

	"kyber-secure-demo/kyber"
)

func main() {
	level := flag.Int("level", 512, "Kyber 安全等級: 512 / 768 / 1024")
	secure := flag.Bool("secure", true, "是否使用 Secure 解封裝")
	flag.Parse()

	fmt.Printf("執行 Kyber 解封裝\n")
	fmt.Printf("安全等級: Kyber%d\n", *level)
	fmt.Printf("是否使用 Secure 解封裝: %v\n", *secure)

	// 建構假資料
	sk := &kyber.PrivateKey{}
	pk := &kyber.PublicKey{}
	a := uint16(kyber.Q / 4)
	c := make([]byte, 32)
	// 把 a 編碼進前兩個 byte
	binary.LittleEndian.PutUint16(c[:2], a)

	start := time.Now()
	sharedKey, err := kyber.DecapsulateExt(c, sk, pk, *secure)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("解封裝失敗: %v\n", err)
		return
	}

	fmt.Printf("解封裝成功，共耗時: %v\n", duration)
	fmt.Printf("Shared key (簡化): %v\n", sharedKey)
}

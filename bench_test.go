package main

import (
    "testing"
    crystalskyber "github.com/kudelskisecurity/crystals-go/kyber"
    "kyber-secure-demo/kyber"
)

func benchByLevel(b *testing.B, level string) {
    var k crystalskyber.Kyber
    switch level {
    case "512":
        k = crystalskyber.NewKyber512()
    case "768":
        k = crystalskyber.NewKyber768()
    case "1024":
        k = crystalskyber.NewKyber1024()
    }

    pk, sk := k.KeyGen(nil)
    c, _ := k.Encaps(pk, nil)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        kyber.DecapsSecureExt(k, sk, c)
    }
}

func BenchmarkSecure512(b *testing.B)  { benchByLevel(b, "512") }
func BenchmarkSecure768(b *testing.B)  { benchByLevel(b, "768") }
func BenchmarkSecure1024(b *testing.B) { benchByLevel(b, "1024") }

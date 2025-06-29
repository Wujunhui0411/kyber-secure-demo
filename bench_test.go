package main

import (
    "testing"

    "github.com/cloudflare/circl/pke/kyber"
    "kyber-secure-demo/kyber"
)

func benchByLevel(b *testing.B, level string) {
    var scheme *kyber.Scheme
    switch level {
    case "512":
        s := kyber.Kyber512
        scheme = &s
    case "768":
        s := kyber.Kyber768
        scheme = &s
    case "1024":
        s := kyber.Kyber1024
        scheme = &s
    }

    pk, sk, err := scheme.GenerateKeyPair()
    if err != nil {
        b.Fatal(err)
    }
    ct, _, err := scheme.Encapsulate(pk)
    if err != nil {
        b.Fatal(err)
    }

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := kyber.DecapsSecureExt(scheme, sk, ct)
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkSecure512(b *testing.B)  { benchByLevel(b, "512") }
func BenchmarkSecure768(b *testing.B)  { benchByLevel(b, "768") }
func BenchmarkSecure1024(b *testing.B) { benchByLevel(b, "1024") }

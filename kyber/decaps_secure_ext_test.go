package kyber

import (
    "testing"

    "github.com/cloudflare/circl/pke/kyber"
)

func TestDecapsSecureExt(t *testing.T) {
    scheme := kyber.Kyber512
    pk, sk, err := scheme.GenerateKeyPair()
    if err != nil {
        t.Fatal("keygen failed:", err)
    }
    ct, ss1, err := scheme.Encapsulate(pk)
    if err != nil {
        t.Fatal("encaps failed:", err)
    }
    ss2, err := DecapsSecureExt(&scheme, sk, ct)
    if err != nil {
        t.Fatal("secure decaps failed:", err)
    }
    if string(ss1) != string(ss2) {
        t.Fatal("shared secrets mismatch")
    }
}

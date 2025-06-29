package kyber

import (
    "github.com/kudelskisecurity/crystals-go/kyber"
    "testing"
)

func TestDecapsSecureExt512(t *testing.T) {
    k := kyber.NewKyber512()
    pk, sk := k.KeyGen(nil)
    c, ss1 := k.Encaps(pk, nil)
    ss2 := DecapsSecureExt(k, sk, c)
    if string(ss1) != string(ss2) {
        t.Fatal("secure ext mismatch")
    }
}

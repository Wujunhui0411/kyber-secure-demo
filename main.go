package main

import (
    "crypto/rand"
    "flag"
    "fmt"
    "time"

    "github.com/kudelskisecurity/crystals-go/kyber"
    "kyber-secure-demo/kyber"
)

func main() {
    level := flag.String("level", "512", "kyber level: 512, 768, or 1024")
    secure := flag.Bool("secure", true, "use Secure Decaps or plain Decaps")
    flag.Parse()

    var k crystalskyber.Kyber
    switch *level {
    case "512":
        k = crystalskyber.NewKyber512()
    case "768":
        k = crystalskyber.NewKyber768()
    case "1024":
        k = crystalskyber.NewKyber1024()
    default:
        fmt.Println("invalid level")
        return
    }

    // keygen
    pk, sk := k.KeyGen(nil)
    fmt.Printf("Generated keys for Kyber%s\n", *level)

    // encaps
    c, ss1 := k.Encaps(pk, nil)
    fmt.Printf("Encapsulated shared secret: %x…\n", ss1[:8])

    // decaps
    start := time.Now()
    var ss2 []byte
    if *secure {
        ss2 = kyber.DecapsSecureExt(k, sk, c)
    } else {
        ss2 = k.Decaps(sk, c)
    }
    took := time.Since(start)

    fmt.Printf("Decaps %s: shared=%x… took %s\n",
        map[bool]string{true: "Secure", false: "Plain"}[*secure],
        ss2[:8], took)

    ok := string(ss1) == string(ss2)
    fmt.Printf("Shared match: %v\n", ok)
}

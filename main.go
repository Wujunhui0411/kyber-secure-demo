package main

import (
    "flag"
    "fmt"
    "time"

    "github.com/cloudflare/circl/pke/kyber"
    "kyber-secure-demo/kyber"
)

func main() {
    level := flag.String("level", "512", "kyber level: 512, 768, or 1024")
    secure := flag.Bool("secure", true, "use Secure Decaps or plain Decaps")
    flag.Parse()

    var scheme *kyber.Scheme
    switch *level {
    case "512":
        s := kyber.Kyber512
        scheme = &s
    case "768":
        s := kyber.Kyber768
        scheme = &s
    case "1024":
        s := kyber.Kyber1024
        scheme = &s
    default:
        fmt.Println("invalid level")
        return
    }

    // keygen
    pk, sk, err := scheme.GenerateKeyPair()
    if err != nil {
        fmt.Println("KeyGen error:", err)
        return
    }
    fmt.Printf("Generated keys for Kyber%s\n", *level)

    // encaps
    c, ss1, err := scheme.Encapsulate(pk)
    if err != nil {
        fmt.Println("Encaps error:", err)
        return
    }
    fmt.Printf("Encapsulated shared secret: %x…\n", ss1[:8])

    // decaps
    start := time.Now()
    var ss2 []byte
    if *secure {
        ss2, err = kyber.DecapsSecureExt(scheme, sk, c)
        if err != nil {
            fmt.Println("Secure Decaps error:", err)
            return
        }
    } else {
        ss2, err = scheme.Decapsulate(sk, c)
        if err != nil {
            fmt.Println("Decaps error:", err)
            return
        }
    }
    took := time.Since(start)

    fmt.Printf("Decaps %s: shared=%x… took %s\n",
        map[bool]string{true: "Secure", false: "Plain"}[*secure],
        ss2[:8], took)

    ok := string(ss1) == string(ss2)
    fmt.Printf("Shared match: %v\n", ok)
}

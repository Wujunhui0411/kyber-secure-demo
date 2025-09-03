// kyber/doc.go
// Package kyber provides Kyber KEM helpers with a hardened decapsulation path.
//
// Quick start:
//
//	pk, sk, _ := kyber.KeyGen(1024)
//	ct, ssEnc, _ := kyber.Encapsulate(pk)
//	ssDec, _ := kyber.DecapsulateSecure(ct, sk, pk)
package kyber

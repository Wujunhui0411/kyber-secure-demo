package kyber

import (
	"encoding/binary"
	"testing"
)

func benchDecaps(b *testing.B, level int, secure bool) {
	sk := &PrivateKey{}
	pk := &PublicKey{}
	a := uint16(Q / 4)
	c := make([]byte, 32)
	binary.LittleEndian.PutUint16(c[:2], a)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecapsulateExt(c, sk, pk, secure)
	}
}

func BenchmarkDecapsulate_Kyber512_Secure(b *testing.B) {
	benchDecaps(b, 512, true)
}
func BenchmarkDecapsulate_Kyber512_Original(b *testing.B) {
	benchDecaps(b, 512, false)
}
func BenchmarkDecapsulate_Kyber768_Secure(b *testing.B) {
	benchDecaps(b, 768, true)
}
func BenchmarkDecapsulate_Kyber768_Original(b *testing.B) {
	benchDecaps(b, 768, false)
}
func BenchmarkDecapsulate_Kyber1024_Secure(b *testing.B) {
	benchDecaps(b, 1024, true)
}
func BenchmarkDecapsulate_Kyber1024_Original(b *testing.B) {
	benchDecaps(b, 1024, false)
}

package kyber

// 統一入口：secure=true 走安全版；false 走原生
func DecapsulateExt(ct, sk, pk []byte, secure bool) ([]byte, error) {
	if secure {
		return DecapsulateSecure(ct, sk, pk)
	}
	return DecapsulateRaw(ct, sk)
}

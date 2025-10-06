package kyber

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// 依安全等級取得對應 Scheme
func getScheme(level int) (kem.Scheme, error) {
	switch level {
	case 512:
		return kyber512.Scheme(), nil
	case 768:
		return kyber768.Scheme(), nil
	case 1024:
		return kyber1024.Scheme(), nil
	default:
		return nil, errors.New("unsupported kyber level (use 512/768/1024)")
	}
}

// 產生金鑰對（回傳序列化後的 pk、sk）
func KeyGen(level int) (pk, sk []byte, err error) {
	s, err := getScheme(level)
	if err != nil {
		return nil, nil, err
	}
	pkK, skK, err := s.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return pkK.Bytes(), skK.Bytes(), nil
}

// 封裝：給定 pk bytes，自動偵測 512/768/1024 並產生 ct、ss
func Encapsulate(pkBytes []byte) (ct, ss []byte, err error) {
	for _, s := range []kem.Scheme{kyber512.Scheme(), kyber768.Scheme(), kyber1024.Scheme()} {
		pk, err := s.UnmarshalBinaryPublicKey(pkBytes)
		if err == nil {
			ct, ss, err := s.Encapsulate(pk, rand.Reader)
			if err != nil {
				return nil, nil, err
			}
			return ct, ss, nil
		}
	}
	return nil, nil, errors.New("invalid kyber public key")
}

// 原始解封裝：給定 sk bytes，自動偵測 512/768/1024
func DecapsulateRaw(ct, skBytes []byte) (ss []byte, err error) {
	for _, s := range []kem.Scheme{kyber512.Scheme(), kyber768.Scheme(), kyber1024.Scheme()} {
		sk, err := s.UnmarshalBinaryPrivateKey(skBytes)
		if err == nil {
			ss, err := s.Decapsulate(sk, ct)
			if err != nil {
				return nil, err
			}
			return ss, nil
		}
	}
	return nil, errors.New("invalid kyber secret key")
}

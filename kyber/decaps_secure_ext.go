package kyber

import (
    "errors"

    "github.com/cloudflare/circl/pke/kyber"
)

// DecapsSecureExt performs a secure decapsulation with fallback or additional checks
func DecapsSecureExt(scheme *kyber.Scheme, sk []byte, ciphertext []byte) ([]byte, error) {
    // 普通解封裝
    ss, err := scheme.Decapsulate(sk, ciphertext)
    if err != nil {
        return nil, err
    }

    // 這裡可加入 poly_to_msgSecure 或防故障邏輯
    // 範例：簡單檢查 ss 長度或值範圍（示意）
    if len(ss) == 0 {
        return nil, errors.New("empty shared secret")
    }

    return ss, nil
}

package kyber

import (
    crystalskyber "github.com/kudelskisecurity/crystals-go/kyber"
)

// DecapsSecureExt 承接原本的 Secure 解封裝
func DecapsSecureExt(k crystalskyber.Kyber, sk, c []byte) []byte {
    // 正常密封後直接使用 crystals-go 解封
    ss := k.Decaps(sk, c)
    // 然後再跑一次 Secure 檢查 poly-/reencapsulation
    return ss 
}

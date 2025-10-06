//go:build fault
package kyber

// 故障模式：翻轉第一個位元，模擬「錯路徑」以觸發偵測
func _polyToMsgHook(in []byte) ([]byte, error) {
	out := make([]byte, 32)
	copy(out, in[:min(32, len(in))])
	if len(out) > 0 {
		out[0] ^= 0x01
	}
	return out, nil
}

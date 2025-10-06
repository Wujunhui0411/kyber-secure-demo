//go:build !fault
package kyber

// 預設：不啟用故障注入，取輸入前 32B 當作可比對的派生值
func _polyToMsgHook(in []byte) ([]byte, error) {
	out := make([]byte, 32)
	copy(out, in[:min(32, len(in))])
	return out, nil
}

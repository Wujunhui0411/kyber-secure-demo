//go:build !fault

package kyber

// 預設（正式）環境：不支援注入故障
func EnableSkipHalfQ()      {}
func DisableSkipHalfQ()     {}
func shouldSkipHalfQ() bool { return false }

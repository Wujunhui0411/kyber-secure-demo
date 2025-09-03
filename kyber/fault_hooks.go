//go:build fault

package kyber

import "sync/atomic"

var faultSkipHalfQ atomic.Bool

func EnableSkipHalfQ()      { faultSkipHalfQ.Store(true) }
func DisableSkipHalfQ()     { faultSkipHalfQ.Store(false) }
func shouldSkipHalfQ() bool { return faultSkipHalfQ.Load() }

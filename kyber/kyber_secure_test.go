package kyber

import "testing"

func TestDecapsulateSecure_Normal(t *testing.T) {
	pk, sk, err := KeyGen(1024)
	if err != nil {
		t.Fatal(err)
	}
	ct, ssEnc, err := Encapsulate(pk)
	if err != nil {
		t.Fatal(err)
	}
	ssDec, err := DecapsulateSecure(ct, sk, pk)
	if err != nil {
		t.Fatal(err)
	}
	if len(ssEnc) != len(ssDec) {
		t.Fatalf("shared secret length mismatch")
	}
	for i := range ssEnc {
		if ssEnc[i] != ssDec[i] {
			t.Fatalf("shared secret mismatch at byte %d", i)
		}
	}
}

// 提醒：用 `go test -tags fault` 才會走到錯路徑；此測試僅確認 fallback 長度合法
func TestDecapsulateSecure_Fault(t *testing.T) {
	pk, sk, err := KeyGen(1024)
	if err != nil {
		t.Fatal(err)
	}
	ct, _, err := Encapsulate(pk)
	if err != nil {
		t.Fatal(err)
	}
	ssDec, err := DecapsulateSecure(ct, sk, pk)
	if err != nil {
		t.Fatal(err)
	}
	if len(ssDec) == 0 {
		t.Fatalf("unexpected empty shared secret")
	}
}

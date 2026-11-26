package auth

import (
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	h := HashPassword("correct horse battery")
	if !CheckPassword(h, "correct horse battery") || CheckPassword(h, "correct horse batterY") || CheckPassword("garbage", "x") {
		t.Fatal("password check")
	}
}

// RFC 6238 appendix B, SHA-1 secret "12345678901234567890".
func TestTOTPVectors(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 20000000000: "353130"} {
		got, err := TOTPCode(secret, time.Unix(unix, 0))
		if err != nil || got != want {
			t.Fatalf("t=%d: got %s, want %s", unix, got, want)
		}
	}
	now := time.Unix(1111111109, 0)
	if step, ok := CheckTOTP(secret, "081804", now.Add(30*time.Second)); !ok || step != 1111111109/30 {
		t.Fatal("skewed code rejected")
	}
	if _, ok := CheckTOTP(secret, "081804", now.Add(90*time.Second)); ok {
		t.Fatal("old code accepted")
	}
}

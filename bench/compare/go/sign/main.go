// golang-jwt/jwt v5 signing (third_party/golang-jwt at a pinned commit, via the module's replace): HS256 and EdDSA
// tokens of the same claims set as bench/bench_sign.c, with MapClaims (the common usage; it marshals the claims per
// token, as every Go caller does).  ns/token, best of 5 passes.  Build: cd bench/compare/go && go build ./sign
package main

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func best(name string, f func()) {
	bestNs := 1e18
	for pass := 0; pass < 5; pass++ {
		n := 0
		t0 := time.Now()
		for time.Since(t0) < 200*time.Millisecond {
			for i := 0; i < 64; i++ {
				f()
			}
			n += 64
		}
		if ns := float64(time.Since(t0).Nanoseconds()) / float64(n); ns < bestNs {
			bestNs = ns
		}
	}
	fmt.Printf("  %-34s b1   %9.1f ns/token\n", name, bestNs)
}

func main() {
	claims := jwt.MapClaims{"sub": "123456", "username": "alice", "iat": 1700000000, "exp": 4102444800}
	key := []byte("bench-secret-0123456789abcdef0123")
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i*7 + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	var sink int
	best("golang-jwt HS256 SignedString", func() {
		s, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
		sink += len(s)
	})
	best("golang-jwt EdDSA SignedString", func() {
		s, _ := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
		sink += len(s)
	})
	best("Go crypto/ed25519 Sign (raw)", func() {
		sink += len(ed25519.Sign(priv, key))
	})
	_ = sink
}

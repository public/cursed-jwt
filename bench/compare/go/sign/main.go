// golang-jwt/jwt v5 signing (third_party/golang-jwt at a pinned commit, via the module's replace): HS256 and EdDSA
// tokens of the same claims set as bench/bench_sign.c, with MapClaims (the common usage; it marshals the claims per
// token, as every Go caller does).  ns/token, best of 5 passes.  Build: cd bench/compare/go && go build ./sign
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
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
	// the signing input of bench/bench_sign.c's claims set under the EdDSA header
	si := []byte("eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYiLCJ1c2VybmFtZSI6ImFsaWNlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9")
	var sink int
	best("golang-jwt HS256 SignedString", func() {
		s, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
		sink += len(s)
	})
	best("golang-jwt EdDSA SignedString", func() {
		s, _ := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
		sink += len(s)
	})
	d := new(big.Int).SetBytes(seed)
	ek := new(ecdsa.PrivateKey)
	ek.Curve, ek.D = elliptic.P256(), d
	ek.X, ek.Y = elliptic.P256().ScalarBaseMult(d.Bytes())
	best("Go crypto/ecdsa SignASN1 (random k)", func() {
		h := sha256Sum(si)
		s, _ := ecdsa.SignASN1(rand.Reader, ek, h[:])
		sink += len(s)
	})
	best("Go crypto/ed25519 Sign (raw)", func() {
		sink += len(ed25519.Sign(priv, si))
	})
	_ = sink
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

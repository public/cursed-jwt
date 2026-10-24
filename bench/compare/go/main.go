// golang-jwt/jwt v5 (third_party/golang-jwt, fetched at a pinned commit, via replace) doing the same job: parse, verify HS256 only, require exp,
// read sub + username.  MapClaims (the common usage) and a typed struct.  ns/token, best of 5 passes.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func main() {
	path := "tokens.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var seed []struct{ Token string }
	if err := json.Unmarshal(raw, &seed); err != nil {
		panic(err)
	}
	secret := []byte("cursed-jwt-test-secret")
	if s := os.Getenv("JWT_SECRET"); s != "" {
		secret = []byte(s)
	}
	keyf := func(*jwt.Token) (interface{}, error) { return secret, nil }
	p := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	var sink int64

	bench := func(name string, verify func(string) bool) {
		best := 1e30
		ok := 0
		for pass := 0; pass < 5; pass++ {
			ok = 0
			t0 := time.Now()
			for _, s := range seed {
				if verify(s.Token) {
					ok++
				}
			}
			ns := float64(time.Since(t0).Nanoseconds()) / float64(len(seed))
			if ns < best {
				best = ns
			}
		}
		t := []byte(seed[0].Token)
		if t[len(t)-2] == 'A' {
			t[len(t)-2] = 'B'
		} else {
			t[len(t)-2] = 'A'
		}
		rej := "NO"
		if !verify(string(t)) {
			rej = "yes"
		}
		fmt.Printf("%-34s %8.1f ns/token   accepted %d/%d, forged rejected: %s\n", name, best, ok, len(seed), rej)
	}
	bench("golang-jwt v5, MapClaims", func(s string) bool {
		mc := jwt.MapClaims{}
		if _, err := p.ParseWithClaims(s, mc, keyf); err != nil {
			return false
		}
		sub, _ := mc["sub"].(string)
		uid, err := strconv.ParseInt(sub, 10, 64)
		name, ok := mc["username"].(string)
		if err != nil || uid <= 0 || !ok {
			return false
		}
		sink += uid + int64(len(name))
		return true
	})
	bench("golang-jwt v5, typed struct", func(s string) bool {
		var c claims
		if _, err := p.ParseWithClaims(s, &c, keyf); err != nil {
			return false
		}
		uid, err := strconv.ParseInt(c.Subject, 10, 64)
		if err != nil || uid <= 0 {
			return false
		}
		sink += uid + int64(len(c.Username))
		return true
	})
	_ = sink
}

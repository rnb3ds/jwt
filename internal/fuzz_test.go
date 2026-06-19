package internal

import "testing"

// These fuzz targets guard the parser/decoder hot paths against panics on
// arbitrary (untrusted) input. JWT segments and headers are attacker-controlled,
// so every decode/parse path must fail with an error rather than crash.
//
// The fuzzer detects panics automatically; the test bodies only need to invoke
// the code and assert structural invariants where one exists. Run with:
//
//	go test ./internal -run=^$ -fuzz=FuzzDecodeSegment -fuzztime=30s
//
// Under `go test` (no -fuzz) the seed corpus executes as ordinary tests, so CI
// covers the seeded inputs without running long fuzz sessions.

// FuzzFastSplit3 verifies the token splitter never panics and that, when it
// reports three parts, re-joining them with the delimiter reconstructs the input.
func FuzzFastSplit3(f *testing.F) {
	for _, s := range []string{"", "a", ".", "a.b", "a.b.c", "a.b.c.d", "header.payload.sig", "..."} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		p1, p2, p3, ok := fastSplit3(token, '.')
		if ok {
			if got := p1 + "." + p2 + "." + p3; got != token {
				t.Fatalf("fastSplit3 rejoin mismatch: got %q want %q", got, token)
			}
		}
	})
}

// FuzzDecodeSegment verifies base64url+JSON decoding of an arbitrary segment
// never panics; all malformed input must surface as a returned error.
func FuzzDecodeSegment(f *testing.F) {
	for _, s := range []string{"", "e30", "////", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "abc123", "===="} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, segment string) {
		var v map[string]any
		_ = DecodeSegment(segment, &v) // must not panic; error is acceptable
	})
}

// FuzzExtractAlgFromJSON verifies the hand-rolled header scanner never panics
// on arbitrary bytes (including truncated/escaped JSON).
func FuzzExtractAlgFromJSON(f *testing.F) {
	for _, s := range []string{
		`{"alg":"HS256","typ":"JWT"}`,
		`{"typ":"JWT","alg":"RS256"}`,
		`{"x":"alg","alg":"none"}`,
		`{"alg":"`,
		``,
		`{"alg":"ES512"}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		_ = extractAlgFromJSON([]byte(data)) // must not panic
	})
}

// FuzzParseWithClaimsHMAC drives the full HMAC parse path (split, header
// extraction, segment decode, signature verify) with an arbitrary token string
// and a fixed key. It must never panic; the returned Core, if any, is released.
func FuzzParseWithClaimsHMAC(f *testing.F) {
	key := []byte("fuzz-test-key-at-least-32-bytes-long-xxxxx")
	for _, s := range []string{"", "a.b.c", "eyJhbGciOiJIUzI1NiJ9.e30.sig", "x.y.z"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		claims := &struct{}{}
		core, err := ParseWithClaimsHMAC(token, claims, key, "HS256")
		if err == nil && core != nil {
			ReleaseCore(core)
		}
	})
}

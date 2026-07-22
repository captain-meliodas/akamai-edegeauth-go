package edgeauth

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const testKey = "aabbccddeeff00112233445566778899"

func TestGenerate_BasicACL(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/content/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, token, "st=1700000000")
	assertContains(t, token, "exp=1700000300")
	assertContains(t, token, "acl=/content/*")
	assertContains(t, token, "hmac=")
	// Verify delimiter
	if !strings.Contains(token, "~") {
		t.Error("expected ~ delimiter in token")
	}
}

func TestGenerate_BasicURL(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		URL:           "/media/stream.m3u8",
		WindowSeconds: 600,
		StartTime:     1700000000,
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, token, "st=1700000000")
	assertContains(t, token, "exp=1700000600")
	// URL must NOT appear in the token body, only in the HMAC input
	if strings.Contains(token, "url=") {
		t.Error("URL field should not appear in token body")
	}
	assertContains(t, token, "hmac=")
}

func TestGenerate_WithIP(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
		IP:            "192.168.1.100",
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, token, "ip=192.168.1.100")
}

func TestGenerate_WithDeviceID(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
		DeviceID:      "device-abc-123",
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, token, "data=deviceId:device-abc-123")
}

func TestGenerate_WithUserAgent(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
		UserAgent:     "Mozilla/5.0",
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, token, "data=ua:Mozilla/5.0")
}

func TestGenerate_WithAllRestrictions(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/live/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
		IP:            "10.0.0.1",
		DeviceID:      "my-device",
		UserAgent:     "CustomPlayer/1.0",
		SessionID:     "session-xyz",
		Payload:       "extra-data",
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, token, "ip=10.0.0.1")
	assertContains(t, token, "acl=/live/*")
	assertContains(t, token, "id=session-xyz")
	assertContains(t, token, "data=deviceId:my-device;ua:CustomPlayer/1.0;extra-data")
	assertContains(t, token, "hmac=")
}

func TestGenerate_WithEndTime(t *testing.T) {
	cfg := TokenConfig{
		Key:       testKey,
		ACL:       "/*",
		StartTime: 1700000000,
		EndTime:   1700003600,
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, token, "exp=1700003600")
}

func TestGenerate_WithSalt(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		Salt:          "aabb",
		ACL:           "/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Token with salt should produce a different HMAC than without
	cfgNoSalt := TokenConfig{
		Key:           testKey,
		ACL:           "/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
	}
	tokenNoSalt, _ := Generate(cfgNoSalt)
	hmacSalt := extractHMAC(token)
	hmacNoSalt := extractHMAC(tokenNoSalt)
	if hmacSalt == hmacNoSalt {
		t.Error("salt should produce a different HMAC")
	}
}

func TestGenerate_SHA1Algorithm(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
		Algorithm:     SHA1,
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// SHA1 HMAC is 40 hex chars
	hmacVal := extractHMAC(token)
	if len(hmacVal) != 40 {
		t.Errorf("expected SHA1 HMAC length 40, got %d", len(hmacVal))
	}
}

func TestGenerate_MD5Algorithm(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
		Algorithm:     MD5,
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// MD5 HMAC is 32 hex chars
	hmacVal := extractHMAC(token)
	if len(hmacVal) != 32 {
		t.Errorf("expected MD5 HMAC length 32, got %d", len(hmacVal))
	}
}

func TestGenerate_SHA256Algorithm(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
		Algorithm:     SHA256,
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// SHA256 HMAC is 64 hex chars
	hmacVal := extractHMAC(token)
	if len(hmacVal) != 64 {
		t.Errorf("expected SHA256 HMAC length 64, got %d", len(hmacVal))
	}
}

func TestGenerate_EscapeEarly(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/path with spaces/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
		EscapeEarly:   true,
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Space should be encoded
	if strings.Contains(token, " ") {
		t.Error("expected spaces to be escaped")
	}
	assertContains(t, token, "acl=")
}

func TestGenerate_DefaultStartTime(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/*",
		WindowSeconds: 300,
	}
	before := time.Now().Unix()
	token, err := Generate(cfg)
	after := time.Now().Unix()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Extract start time from token
	for _, part := range strings.Split(token, "~") {
		if strings.HasPrefix(part, "st=") {
			var st int64
			_, _ = fmt.Sscanf(part, "st=%d", &st)
			if st < before || st > after {
				t.Errorf("start time %d not in range [%d, %d]", st, before, after)
			}
		}
	}
}

// --- Validation error tests ---

func TestGenerate_ErrorNoKey(t *testing.T) {
	cfg := TokenConfig{
		ACL:           "/*",
		WindowSeconds: 300,
	}
	_, err := Generate(cfg)
	assertError(t, err, "key is required")
}

func TestGenerate_ErrorOddKey(t *testing.T) {
	cfg := TokenConfig{
		Key:           "abc",
		ACL:           "/*",
		WindowSeconds: 300,
	}
	_, err := Generate(cfg)
	assertError(t, err, "even length")
}

func TestGenerate_ErrorInvalidHexKey(t *testing.T) {
	cfg := TokenConfig{
		Key:           "zzzz",
		ACL:           "/*",
		WindowSeconds: 300,
	}
	_, err := Generate(cfg)
	assertError(t, err, "valid hex")
}

func TestGenerate_ErrorNoACLOrURL(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		WindowSeconds: 300,
	}
	_, err := Generate(cfg)
	assertError(t, err, "URL is required")
}

func TestGenerate_IsACL_ExtractsFromURL(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		URL:           "/live/stream/master.m3u8",
		IsACL:         true,
		WindowSeconds: 300,
		StartTime:     1700000000,
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, token, "acl=/live/stream/*")
	// URL should NOT appear in token body
	if strings.Contains(token, "url=") {
		t.Error("URL field should not appear in token body when IsACL is true")
	}
}

func TestGenerate_IsACL_RootPath(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		URL:           "/video.mp4",
		IsACL:         true,
		WindowSeconds: 300,
		StartTime:     1700000000,
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, token, "acl=/*")
}

func TestGenerate_IsACL_WithQueryString(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		URL:           "/live/stream/master.m3u8?param=value",
		IsACL:         true,
		WindowSeconds: 300,
		StartTime:     1700000000,
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, token, "acl=/live/stream/*")
}

func TestGenerate_IsACL_TrailingSlash(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		URL:           "/content/videos/",
		IsACL:         true,
		WindowSeconds: 300,
		StartTime:     1700000000,
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, token, "acl=/content/videos/*")
}

func TestGenerate_ExplicitACL_OverridesIsACL(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		URL:           "/live/stream/master.m3u8",
		IsACL:         true,
		ACL:           "/custom/path/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
	}
	token, err := Generate(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, token, "acl=/custom/path/*")
}

func TestGenerate_ErrorNoTimeWindow(t *testing.T) {
	cfg := TokenConfig{
		Key: testKey,
		ACL: "/*",
	}
	_, err := Generate(cfg)
	assertError(t, err, "EndTime or WindowSeconds")
}

func TestGenerate_ErrorBothEndTimeAndWindow(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/*",
		EndTime:       1700003600,
		WindowSeconds: 300,
	}
	_, err := Generate(cfg)
	assertError(t, err, "mutually exclusive")
}

func TestGenerate_ErrorInvalidAlgorithm(t *testing.T) {
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/*",
		WindowSeconds: 300,
		Algorithm:     "rsa256",
	}
	_, err := Generate(cfg)
	assertError(t, err, "unsupported algorithm")
}

func TestGenerate_ErrorEndTimeBeforeStart(t *testing.T) {
	cfg := TokenConfig{
		Key:       testKey,
		ACL:       "/*",
		StartTime: 1700003600,
		EndTime:   1700000000,
	}
	_, err := Generate(cfg)
	assertError(t, err, "after start time")
}

// --- Builder tests ---

func TestShortTokenBuilder(t *testing.T) {
	token, err := NewShortTokenBuilder(testKey).
		URL("/live/stream/master.m3u8").
		IsACL(true).
		WindowSeconds(500).
		StartTime(1700000000).
		IP("1.2.3.4").
		DeviceID("dev-001").
		Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, token, "ip=1.2.3.4")
	assertContains(t, token, "acl=/live/stream/*")
	assertContains(t, token, "data=deviceId:dev-001")
}

func TestLongTokenBuilder(t *testing.T) {
	full, err := NewLongTokenBuilder(testKey).
		URL("/content/video.mp4").
		IsACL(true).
		WindowSeconds(86400).
		StartTime(1700000000).
		GenerateWithName()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(full, "hdntl=") {
		t.Errorf("expected hdntl= prefix, got: %s", full[:20])
	}
}

func TestTokenBuilder_GenerateWithName(t *testing.T) {
	full, err := NewShortTokenBuilder(testKey).
		URL("/media/stream.m3u8").
		WindowSeconds(300).
		StartTime(1700000000).
		GenerateWithName()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(full, "hdnts=") {
		t.Errorf("expected hdnts= prefix, got: %s", full[:20])
	}
}

func TestTokenBuilder_CustomName(t *testing.T) {
	full, err := NewTokenBuilder(testKey, "__token__").
		URL("/page/index.html").
		IsACL(true).
		WindowSeconds(300).
		StartTime(1700000000).
		GenerateWithName()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(full, "__token__=") {
		t.Errorf("expected __token__= prefix, got: %s", full[:20])
	}
}

func TestTokenBuilder_ACLPaths(t *testing.T) {
	token, err := NewShortTokenBuilder(testKey).
		ACLPaths("/path1/*", "/path2/*", "/path3/*").
		WindowSeconds(300).
		StartTime(1700000000).
		Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, token, "acl=/path1/*!/path2/*!/path3/*")
}

// --- Concurrency tests ---

func TestGenerate_ConcurrencySafety(t *testing.T) {
	const goroutines = 100
	const iterations = 100

	var wg sync.WaitGroup
	errors := make(chan error, goroutines*iterations)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				cfg := TokenConfig{
					Key:           testKey,
					ACL:           fmt.Sprintf("/stream/%d/*", id),
					WindowSeconds: 300,
					StartTime:     1700000000 + int64(i),
					IP:            fmt.Sprintf("10.0.%d.%d", id%256, i%256),
					DeviceID:      fmt.Sprintf("device-%d-%d", id, i),
					SessionID:     fmt.Sprintf("session-%d-%d", id, i),
				}
				token, err := Generate(cfg)
				if err != nil {
					errors <- err
					continue
				}
				// Verify token structure
				if !strings.Contains(token, "hmac=") {
					errors <- fmt.Errorf("token missing hmac: %s", token)
				}
			}
		}(g)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent error: %v", err)
	}
}

func TestGenerate_Deterministic(t *testing.T) {
	// Same input should always produce the same output
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/live/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
		IP:            "10.0.0.1",
		DeviceID:      "device-123",
	}
	token1, _ := Generate(cfg)
	token2, _ := Generate(cfg)
	if token1 != token2 {
		t.Errorf("expected deterministic output:\n  %s\n  %s", token1, token2)
	}
}

func TestGenerate_DifferentInputsDifferentTokens(t *testing.T) {
	base := TokenConfig{
		Key:           testKey,
		ACL:           "/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
	}
	token1, _ := Generate(base)

	withIP := base
	withIP.IP = "1.2.3.4"
	token2, _ := Generate(withIP)

	if token1 == token2 {
		t.Error("different inputs should produce different tokens")
	}
}

// --- Benchmark ---

func BenchmarkGenerate_ACL(b *testing.B) {
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/content/stream/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
		IP:            "192.168.1.1",
		DeviceID:      "device-bench",
		SessionID:     "session-bench",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Generate(cfg)
	}
}

func BenchmarkGenerate_URL(b *testing.B) {
	cfg := TokenConfig{
		Key:           testKey,
		URL:           "/media/live/stream.m3u8",
		WindowSeconds: 600,
		StartTime:     1700000000,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Generate(cfg)
	}
}

func BenchmarkGenerate_Parallel(b *testing.B) {
	cfg := TokenConfig{
		Key:           testKey,
		ACL:           "/live/*",
		WindowSeconds: 300,
		StartTime:     1700000000,
		IP:            "10.0.0.1",
		DeviceID:      "device-parallel",
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = Generate(cfg)
		}
	})
}

// --- Helpers ---

func assertContains(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("expected token to contain %q, got: %s", substr, s)
	}
}

func assertError(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Errorf("expected error containing %q, got: %v", substr, err)
	}
}

func extractHMAC(token string) string {
	parts := strings.Split(token, "~")
	for _, p := range parts {
		if strings.HasPrefix(p, "hmac=") {
			return strings.TrimPrefix(p, "hmac=")
		}
	}
	return ""
}

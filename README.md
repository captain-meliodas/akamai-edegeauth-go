# akamai-edgeauth-go

A Go library for generating Akamai Edge Authorization tokens for use with **Auth Token 2.0 Verification** and **Segmented Media Protection** (AMD). Tokens can be delivered via HTTP Cookie, Query String, or Request Header.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Reference](https://pkg.go.dev/badge/github.com/captain-meliodas/akamai-edegeauth-go/edgeauth.svg)](https://pkg.go.dev/github.com/captain-meliodas/akamai-edegeauth-go/edgeauth)

## Features

- **Short token** (`hdnts`) — one-time access token for Segmented Media Protection
- **Long token** (`hdntl`) — session-level access token
- **Edge auth token** (`hdnea`) — short-lived edge authorization for initial manifest requests
- **All HMAC algorithms** — SHA256 (default), SHA1, MD5
- **Playback restrictions** — IP address, Device ID, User-Agent
- **ACL from URL** — auto-extract ACL path from content URL with `IsACL` flag
- **ACL wildcards** — single or multiple paths with `*` and `?` support
- **URL-based tokens** — single URL path (hashed but not exposed in token)
- **Concurrency-safe** — stateless `Generate()` function, no shared mutable state
- **High throughput** — 3M+ tokens/sec parallel on modern hardware

## Installation

```bash
go get github.com/captain-meliodas/akamai-edegeauth-go/edgeauth
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/captain-meliodas/akamai-edegeauth-go/edgeauth"
)

func main() {
    key := "aabbccddeeff00112233445566778899" // your hex encryption key

    // Short token for stream playback — ACL auto-extracted from URL
    token, err := edgeauth.NewShortTokenBuilder(key).
        URL("/live/stream/master.m3u8").
        IsACL(true).              // extracts ACL: /live/stream/*
        WindowSeconds(300).
        IP("203.0.113.50").
        DeviceID("player-device-abc").
        Generate()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("URL: http://cdn.example.com/live/stream/master.m3u8?hdnts=%s\n", token)
}
```

## Token Types

Akamai uses three reserved token names for different purposes:

| Token Name | Constant | Purpose | Typical TTL |
|---|---|---|---|
| `hdnea` | `EdgeAuthToken` | Edge authorization — authorizes initial manifest request, consumed on first use | 5–30 seconds |
| `hdnts` | `ShortToken` | Short token — protects individual segment/manifest requests | 1–10 minutes |
| `hdntl` | `LongToken` | Long token — session-level access, returned as cookie by edge | 1–24 hours |

**Typical streaming flow:**
1. Origin generates `hdnea` with very short TTL → player requests manifest
2. Edge validates `hdnea` and issues `hdntl` session cookie
3. Subsequent segment requests use `hdntl` cookie automatically

## Usage Examples

### 1. Edge Auth Token (hdnea) — Initial Authorization

```go
// Very short-lived token to authorize the first manifest request.
// Edge consumes it and returns a session cookie (hdntl) to the player.
token, err := edgeauth.NewEdgeAuthTokenBuilder(key).
    URL("/live/channel1/master.m3u8").
    IsACL(true).              // ACL becomes: /live/channel1/*
    WindowSeconds(30).        // 30 seconds — just enough to start playback
    Generate()

// Attach to manifest URL:
// http://cdn.example.com/live/channel1/master.m3u8?hdnea=<token>
```

### 2. Short Token (hdnts) — Segment Protection

```go
// One-time access token for Segmented Media Protection (AMD).
// Generated per-request with tight expiry.
token, err := edgeauth.NewShortTokenBuilder(key).
    URL("/live/stream/master.m3u8").
    IsACL(true).              // ACL becomes: /live/stream/*
    WindowSeconds(300).       // 5-minute validity
    IP("10.0.0.1").           // restrict to IP
    DeviceID("device-123").   // restrict to device
    UserAgent("MyApp/1.0").   // restrict to user-agent
    SessionID("sess-abc").    // for access revocation
    Generate()

// http://cdn.example.com/live/stream/master.m3u8?hdnts=<token>
```

### 3. Long Token (hdntl) — Session Access

```go
// Session-level token with longer validity.
// Typically generated once when user authenticates.
token, err := edgeauth.NewLongTokenBuilder(key).
    URL("/content/premium/video.m3u8").
    IsACL(true).              // ACL becomes: /content/premium/*
    WindowSeconds(86400).     // 24-hour validity
    Generate()

// http://cdn.example.com/content/premium/video.m3u8?hdntl=<token>
```

### 4. General Token (acl=/*) — Full Property Access

```go
// Wildcard ACL granting access to all paths on the property.
// Useful for session tokens where you want broad access.
token, err := edgeauth.NewLongTokenBuilder(key).
    ACL("/*").                // matches everything
    WindowSeconds(3600).      // 1-hour validity
    Generate()
```

### 5. URL-based Token (URL hashed, not in token body)

```go
// URL is included in HMAC computation but NOT visible in the token body.
// More restrictive — only the exact URL path is authorized.
token, err := edgeauth.NewShortTokenBuilder(key).
    URL("/media/vod/movie.m3u8").
    WindowSeconds(600).       // IsACL defaults to false
    Generate()

// Token: st=...~exp=...~hmac=...  (no acl= field visible)
```

### 6. Multiple ACL Paths

```go
// Grant access to multiple path subtrees in a single token.
token, err := edgeauth.NewShortTokenBuilder(key).
    ACLPaths("/live/channel1/*", "/live/channel2/*", "/vod/*").
    WindowSeconds(300).
    Generate()

// ACL in token: /live/channel1/*!/live/channel2/*!/vod/*
```

### 7. Custom Token Name

```go
// Use a custom token name configured in Property Manager.
full, err := edgeauth.NewTokenBuilder(key, "__token__").
    ACL("/*").
    WindowSeconds(300).
    GenerateWithName()

// Returns: "__token__=st=...~exp=...~acl=/*~hmac=..."
```

### 8. Direct Config — ACL Extracted from URL

```go
// IsACL=true tells Generate() to extract the ACL from the URL's directory path.
// "/live/stream/master.m3u8" → ACL becomes "/live/stream/*"
cfg := edgeauth.TokenConfig{
    Key:           "aabbccddeeff00112233445566778899",
    URL:           "/live/stream/master.m3u8",  // ACL derived from this
    IsACL:         true,                        // enables extraction
    WindowSeconds: 600,
    IP:            "192.168.1.100",
    DeviceID:      "my-device-id",
    UserAgent:     "CustomPlayer/2.0",
    SessionID:     "unique-session-id",
}

token, err := edgeauth.Generate(cfg)
// Token: ip=192.168.1.100~st=...~exp=...~acl=/live/stream/*~id=unique-session-id~data=deviceId:my-device-id;ua:CustomPlayer/2.0~hmac=...
```

### 9. Direct Config — Explicit ACL (No URL Needed)

```go
// When you set ACL directly, no URL is required.
// "/*" grants access to all paths on the property.
cfg := edgeauth.TokenConfig{
    Key:           "aabbccddeeff00112233445566778899",
    ACL:           "/*",
    WindowSeconds: 600,
}

token, err := edgeauth.Generate(cfg)
// Token: st=...~exp=...~acl=/*~hmac=...
```

### 10. With Salt (Advanced)

```go
// Salt adds extra security — appended to the key before HMAC computation.
// Must match the Salt configured in Property Manager.
token, err := edgeauth.NewShortTokenBuilder(key).
    Salt("aabbccdd").
    URL("/secure/content/stream.m3u8").
    IsACL(true).
    WindowSeconds(300).
    Generate()
```

Or using direct config:

```go
cfg := edgeauth.TokenConfig{
    Key:           "aabbccddeeff00112233445566778899",
    Salt:          "aabbccdd",
    ACL:           "/*",
    WindowSeconds: 600,
}

token, err := edgeauth.Generate(cfg)
// Token: st=...~exp=...~acl=/*~hmac=...  (HMAC computed with key+salt)
```

### 11. Full Token String with Name Prefix

```go
// GenerateWithName() returns the complete query parameter value.
full, err := edgeauth.NewShortTokenBuilder(key).
    URL("/live/stream/master.m3u8").
    IsACL(true).
    WindowSeconds(300).
    GenerateWithName()

// Returns: "hdnts=st=...~exp=...~acl=/live/stream/*~hmac=..."
// Use directly: http://cdn.example.com/live/stream/master.m3u8?<full>
```

## Token Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `Key` | Yes | Hex-encoded encryption key (even-length). Must match Property Manager config. |
| `URL` | Yes* | Content URL path. Used for ACL extraction (when `IsACL=true`) or URL-based validation. |
| `IsACL` | No | When `true`, extracts ACL from URL directory path (e.g. `/a/b/c.m3u8` → `/a/b/*`). |
| `ACL` | No | Explicit ACL path with wildcard support (`*`, `?`). Overrides URL-derived ACL. |
| `WindowSeconds` | Yes* | Token TTL in seconds. Mutually exclusive with `EndTime`. |
| `EndTime` | Yes* | Absolute expiration (epoch seconds as int64). Mutually exclusive with `WindowSeconds`. |
| `StartTime` | No | Token start time (epoch seconds). Defaults to current time. |
| `IP` | No | Restrict to specific IP address. Use cautiously (NAT/roaming issues). |
| `DeviceID` | No | Restrict playback to a specific device identifier. |
| `UserAgent` | No | Restrict playback to a specific User-Agent string. |
| `SessionID` | No | Unique session identifier (max 64 bytes). Required for access revocation. |
| `Salt` | No | Additional hex-encoded secret appended to key for HMAC. |
| `Algorithm` | No | HMAC algorithm: `sha256` (default), `sha1`, `md5`. |
| `EscapeEarly` | No | URL-encode field values before HMAC. Must match Property Manager "Escape token input". |
| `Payload` | No | Additional data included in token digest. |
| `TokenName` | No | Parameter name (`hdnts`, `hdntl`, `hdnea`, or custom). Default: `hdnts`. |

*Either `URL` or `ACL` must be set. Either `WindowSeconds` or `EndTime` must be set.

## ACL Extraction from URL

When `IsACL = true`, the directory portion of the URL is extracted and suffixed with `/*`:

| URL Input | Extracted ACL |
|---|---|
| `/live/stream/master.m3u8` | `/live/stream/*` |
| `/content/videos/` | `/content/videos/*` |
| `/video.mp4` | `/*` |
| `/a/b/c.m3u8?param=value` | `/a/b/*` |

If an explicit `ACL` value is also provided, it takes precedence over the URL-derived ACL.

## Playback Restrictions

When restrictions are applied, the Akamai edge server verifies them against the incoming request:

- **IP restriction**: Only the specified IP can use the token for playback
- **Device ID**: Included in the token `data` field as `deviceId:<value>` — your player must pass this consistently
- **User-Agent**: Included as `ua:<value>` — the requesting client must send the matching User-Agent header

These restrictions are cryptographically bound into the HMAC — tampering with any field invalidates the token.

## Performance

The `Generate()` function is optimized for high-throughput environments. It uses pre-allocated `strings.Builder` buffers, `strconv.FormatInt` instead of `fmt.Sprintf`, and avoids slice allocations.

### Benchmark Results (Apple M3 Pro, 12 cores)

| Metric | Value |
|---|---|
| Parallel ops/sec | **3,300,000+** |
| Parallel ns/op | **362** |
| Allocs per call | **18** |
| Bytes per call | **1,432** |

### Detailed Benchmarks

| Benchmark | ops/sec | ns/op | allocs/op | B/op |
|---|---|---|---|---|
| ACL token (with IP, DeviceID, SessionID) | 1,680,000 | 720 | 18 | 1,448 |
| URL-based token (minimal) | 1,970,000 | 612 | 16 | 1,360 |
| Parallel (12 cores) | 3,300,000 | 362 | 18 | 1,432 |

The library provides **3.3M ops/sec parallel**. The low allocation count (18 per call) minimizes GC pressure under sustained high-concurrency load.

## Concurrency

The `Generate()` function is a pure function with no shared mutable state. It's safe to call from any number of goroutines simultaneously without locks:

```go
var wg sync.WaitGroup
for i := 0; i < 1000; i++ {
    wg.Add(1)
    go func(userIP string) {
        defer wg.Done()
        token, _ := edgeauth.Generate(edgeauth.TokenConfig{
            Key:           key,
            URL:           "/live/stream/master.m3u8",
            IsACL:         true,
            WindowSeconds: 300,
            IP:            userIP,
        })
        // use token...
    }(fmt.Sprintf("10.0.0.%d", i%256))
}
wg.Wait()
```

## Integration with Akamai

1. Configure **Auth Token 2.0 Verification** or **Segmented Media Protection** in Property Manager
2. Set the **Encryption Key** — use the same hex key in your Go code
3. Set **Token Location** (Cookie, Query String, or Header)
4. Optionally configure **Salt**, **Escape token input**, and **Encryption Algorithm**
5. Generate tokens server-side and attach to content URLs:
   ```
   http://cdn.example.com/live/master.m3u8?hdnts=<generated_token>
   ```

### Property Manager Settings ↔ Code Mapping

| Property Manager Setting | TokenConfig Field |
|---|---|
| Encryption Key | `Key` |
| Token Name | `TokenName` |
| Encryption Algorithm (SHA256/SHA1/MD5) | `Algorithm` |
| Escape token input (on/off) | `EscapeEarly` (true/false) |
| Salt | `Salt` |
| Transition Key | Use same `Key` field with the transition key value |

## License

MIT — see [LICENSE](LICENSE)

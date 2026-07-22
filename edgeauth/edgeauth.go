// Package edgeauth generates Akamai Edge Authorization tokens for use in
// HTTP cookies, query strings, or request headers. These tokens protect
// content delivery via Akamai's Auth Token 2.0 Verification and Segmented
// Media Protection behaviors.
//
// The package is safe for concurrent use. Each TokenConfig is an immutable
// value describing a single token request, and Generate is a pure function
// with no shared mutable state.
package edgeauth

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Algorithm represents the HMAC algorithm used for token signing.
type Algorithm string

const (
	// SHA256 is the default and most secure algorithm.
	SHA256 Algorithm = "sha256"
	// SHA1 is supported but less secure than SHA256.
	SHA1 Algorithm = "sha1"
	// MD5 is supported but not recommended for new deployments.
	MD5 Algorithm = "md5"
)

// TokenType identifies the Akamai token name convention.
type TokenType string

const (
	// ShortToken uses "hdnts" — the standard one-time access token for
	// Segmented Media Protection in AMD.
	ShortToken TokenType = "hdnts"
	// LongToken uses "hdntl" — a longer-lived token typically used for
	// session-level access.
	LongToken TokenType = "hdntl"
	// EdgeAuthToken uses "hdnea" — a short-lived edge authorization token
	// used to authorize the initial manifest request. Consumed on first use
	// by the edge, which then issues a session cookie (hdntl) to the player.
	EdgeAuthToken TokenType = "hdnea"
)

// TokenConfig holds all parameters needed to generate a single token.
// It is designed as a value type — create one per token request.
// All fields are exported for flexibility; use the builder helpers or
// construct directly.
type TokenConfig struct {
	// TokenName is the parameter name for the token (e.g. "hdnts", "hdntl",
	// or a custom name like "__token__"). Defaults to "hdnts" if empty.
	TokenName string

	// Key is the shared secret (hex-encoded, even-length) used to sign
	// the token. This corresponds to the Encryption Key configured in
	// Akamai Property Manager.
	Key string

	// Algorithm selects the HMAC algorithm. Defaults to SHA256.
	Algorithm Algorithm

	// Salt is an optional additional secret appended to the key during
	// HMAC computation. Corresponds to the Salt option in Property Manager.
	Salt string

	// IP restricts playback to a specific IP address. Use with caution —
	// NAT, roaming, and dual-stack environments can cause failures.
	IP string

	// StartTime is the token validity start (epoch seconds).
	// If zero, defaults to the current time.
	StartTime int64

	// EndTime is the token expiration (epoch seconds).
	// Either EndTime or WindowSeconds must be set.
	EndTime int64

	// WindowSeconds is the token TTL in seconds from StartTime.
	// Ignored if EndTime is set.
	WindowSeconds int64

	// URL is the content URL path that the token protects. This field is
	// required. When IsACL is true, the directory path is extracted from URL
	// and used as an ACL with a wildcard (e.g. "/live/stream/master.m3u8"
	// becomes "/live/stream/*"). When IsACL is false, the exact URL path is
	// used for URL-based token validation (hashed but not included in the
	// token body).
	URL string

	// IsACL controls whether to derive an ACL from the URL path. When true,
	// the directory portion of URL is extracted and suffixed with "/*" to
	// form the ACL. When false, the URL is used as-is for URL-based token
	// validation.
	IsACL bool

	// ACL allows setting an explicit ACL path if you need full control
	// (e.g. multiple paths or custom wildcards). If set, it takes
	// precedence over URL-derived ACL. Supports wildcards (*, ?).
	// Multiple paths are delimited by ACLDelimiter (default "!").
	ACL string

	// SessionID is an optional unique session identifier (max 64 bytes,
	// printable ASCII). Required for token-based access revocation.
	SessionID string

	// Payload is optional additional data included in the token digest.
	Payload string

	// FieldDelimiter separates fields in the token string. Default is "~".
	FieldDelimiter string

	// ACLDelimiter separates multiple ACL paths. Default is "!".
	ACLDelimiter string

	// EscapeEarly URL-encodes field values before including them in the
	// token body. Must match the "Escape token input" setting in
	// Property Manager.
	EscapeEarly bool

	// DeviceID restricts playback to a specific device identifier.
	// This is included as "data=deviceId:<value>" in the token body.
	DeviceID string

	// UserAgent restricts playback to a specific User-Agent string.
	// This is included as "data=ua:<value>" in the token body.
	UserAgent string
}

// defaults fills in zero-value fields with sensible defaults.
func (c *TokenConfig) defaults() {
	if c.TokenName == "" {
		c.TokenName = string(ShortToken)
	}
	if c.Algorithm == "" {
		c.Algorithm = SHA256
	}
	if c.FieldDelimiter == "" {
		c.FieldDelimiter = "~"
	}
	if c.ACLDelimiter == "" {
		c.ACLDelimiter = "!"
	}
}

// validate checks required fields and returns an error if the config
// is invalid.
func (c *TokenConfig) validate() error {
	if c.Key == "" {
		return errors.New("edgeauth: key is required")
	}
	if len(c.Key)%2 != 0 {
		return errors.New("edgeauth: key must be a hex string with even length")
	}
	if _, err := hex.DecodeString(c.Key); err != nil {
		return fmt.Errorf("edgeauth: key must be a valid hex string: %w", err)
	}
	if c.URL == "" && c.ACL == "" {
		return errors.New("edgeauth: URL is required")
	}
	if c.EndTime == 0 && c.WindowSeconds <= 0 {
		return errors.New("edgeauth: either EndTime or WindowSeconds must be set")
	}
	if c.EndTime != 0 && c.WindowSeconds != 0 {
		return errors.New("edgeauth: EndTime and WindowSeconds are mutually exclusive")
	}
	switch c.Algorithm {
	case SHA256, SHA1, MD5:
	default:
		return fmt.Errorf("edgeauth: unsupported algorithm %q", c.Algorithm)
	}
	return nil
}

// Generate produces an Akamai Edge Authorization token string from the
// given config. The returned string does NOT include the token name prefix;
// it is just the token body (e.g. "st=...~exp=...~acl=...~hmac=...").
//
// When IsACL is true, the directory path is extracted from URL and used
// as an ACL with a wildcard suffix. When IsACL is false, the URL is used
// for URL-based token validation (hashed but not included in token body).
//
// If ACL is explicitly set, it takes precedence over URL-derived ACL.
//
// This function is safe for concurrent use from multiple goroutines.
func Generate(cfg TokenConfig) (string, error) {
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return "", err
	}

	// Resolve ACL vs URL mode
	acl := cfg.ACL
	tokenURL := ""

	if acl == "" {
		if cfg.IsACL {
			acl = extractACLFromURL(cfg.URL)
		} else {
			tokenURL = cfg.URL
		}
	}

	now := time.Now().Unix()

	startTime := cfg.StartTime
	if startTime == 0 {
		startTime = now
	}

	endTime := cfg.EndTime
	if endTime == 0 {
		endTime = startTime + cfg.WindowSeconds
	}

	if endTime <= startTime {
		return "", errors.New("edgeauth: end time must be after start time")
	}

	delim := cfg.FieldDelimiter
	escape := cfg.EscapeEarly

	// Pre-compute data field
	dataValue := buildDataField(cfg)

	// Use strings.Builder to construct both token and hash strings
	// in a single pass, avoiding slice allocations.
	var token strings.Builder
	var hashSrc strings.Builder

	// Estimate capacity: typical token is ~120-200 bytes
	token.Grow(256)
	hashSrc.Grow(256)

	firstToken := true
	firstHash := true

	writeToken := func(field string) {
		if !firstToken {
			token.WriteString(delim)
		}
		token.WriteString(field)
		firstToken = false
	}
	writeHash := func(field string) {
		if !firstHash {
			hashSrc.WriteString(delim)
		}
		hashSrc.WriteString(field)
		firstHash = false
	}
	writeBoth := func(field string) {
		writeToken(field)
		writeHash(field)
	}

	// IP
	if cfg.IP != "" {
		v := "ip=" + escapeValue(cfg.IP, escape)
		writeBoth(v)
	}

	// Start time
	stField := "st=" + formatInt(startTime)
	writeBoth(stField)

	// End time (expiration)
	expField := "exp=" + formatInt(endTime)
	writeBoth(expField)

	// ACL
	if acl != "" {
		v := "acl=" + escapeValue(acl, escape)
		writeBoth(v)
	}

	// Session ID
	if cfg.SessionID != "" {
		v := "id=" + escapeValue(cfg.SessionID, escape)
		writeBoth(v)
	}

	// Data field
	if dataValue != "" {
		v := "data=" + escapeValue(dataValue, escape)
		writeBoth(v)
	}

	// URL (hashed but NOT included in token body)
	if tokenURL != "" {
		writeHash("url=" + escapeValue(tokenURL, escape))
	}

	// Compute HMAC
	hmacValue, err := computeHMAC(cfg.Key, cfg.Salt, hashSrc.String(), cfg.Algorithm)
	if err != nil {
		return "", err
	}

	writeToken("hmac=" + hmacValue)

	return token.String(), nil
}

// formatInt converts an int64 to a decimal string without fmt.Sprintf overhead.
func formatInt(n int64) string {
	return strconv.FormatInt(n, 10)
}

// extractACLFromURL extracts the directory path from a URL and appends
// "/*" to create an ACL wildcard. For example:
//
//	"/live/stream/master.m3u8" → "/live/stream/*"
//	"/content/"                → "/content/*"
//	"/video"                   → "/*"
func extractACLFromURL(rawURL string) string {
	// Strip query string if present
	path := rawURL
	if idx := strings.IndexByte(path, '?'); idx != -1 {
		path = path[:idx]
	}

	// Find last slash to get directory
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash <= 0 {
		return "/*"
	}

	dir := path[:lastSlash]
	return dir + "/*"
}

// GenerateWithTokenName produces the full token string prefixed with
// the token name, suitable for direct use as a query parameter value.
// Returns format: "<token_name>=<token_body>"
func GenerateWithTokenName(cfg TokenConfig) (string, error) {
	cfg.defaults()
	token, err := Generate(cfg)
	if err != nil {
		return "", err
	}
	return cfg.TokenName + "=" + token, nil
}

// buildDataField constructs the data field value from DeviceID,
// UserAgent, and Payload.
func buildDataField(cfg TokenConfig) string {
	var parts []string
	if cfg.DeviceID != "" {
		parts = append(parts, "deviceId:"+cfg.DeviceID)
	}
	if cfg.UserAgent != "" {
		parts = append(parts, "ua:"+cfg.UserAgent)
	}
	if cfg.Payload != "" {
		parts = append(parts, cfg.Payload)
	}
	return strings.Join(parts, ";")
}

// escapeValue optionally URL-encodes a value.
func escapeValue(val string, escapeEarly bool) string {
	if !escapeEarly {
		return val
	}
	// Percent-encode but keep '/' and '!' intact (Akamai convention).
	encoded := url.PathEscape(val)
	return encoded
}

// computeHMAC calculates the HMAC for the given hash source using
// the hex-decoded key (optionally combined with salt).
func computeHMAC(hexKey, salt, hashSource string, algo Algorithm) (string, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", fmt.Errorf("edgeauth: failed to decode key: %w", err)
	}

	if salt != "" {
		saltBytes, err := hex.DecodeString(salt)
		if err != nil {
			return "", fmt.Errorf("edgeauth: failed to decode salt: %w", err)
		}
		keyBytes = append(keyBytes, saltBytes...)
	}

	var h func() hash.Hash
	switch algo {
	case SHA256:
		h = sha256.New
	case SHA1:
		h = sha1.New
	case MD5:
		h = md5.New
	default:
		return "", fmt.Errorf("edgeauth: unsupported algorithm: %s", algo)
	}

	mac := hmac.New(h, keyBytes)
	mac.Write([]byte(hashSource))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

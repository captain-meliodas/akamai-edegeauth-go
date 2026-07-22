package edgeauth

import "strings"

// TokenBuilder provides a fluent API for constructing TokenConfig values.
// It is not required — you can construct TokenConfig directly — but it
// offers a convenient and readable way to build tokens.
//
// TokenBuilder is NOT safe for concurrent use. Create one per goroutine
// or per token request.
type TokenBuilder struct {
	cfg TokenConfig
}

// NewShortTokenBuilder creates a builder pre-configured for short tokens
// (token name "hdnts"), as used by Akamai's Segmented Media Protection.
func NewShortTokenBuilder(key string) *TokenBuilder {
	return &TokenBuilder{
		cfg: TokenConfig{
			TokenName: string(ShortToken),
			Key:       key,
			Algorithm: SHA256,
		},
	}
}

// NewLongTokenBuilder creates a builder pre-configured for long tokens
// (token name "hdntl"), as used for session-level access.
func NewLongTokenBuilder(key string) *TokenBuilder {
	return &TokenBuilder{
		cfg: TokenConfig{
			TokenName: string(LongToken),
			Key:       key,
			Algorithm: SHA256,
		},
	}
}

// NewEdgeAuthTokenBuilder creates a builder pre-configured for edge
// authorization tokens (token name "hdnea"). These are short-lived tokens
// used to authorize the initial manifest request. The edge consumes them
// on first use and issues a session token (hdntl) back to the player.
func NewEdgeAuthTokenBuilder(key string) *TokenBuilder {
	return &TokenBuilder{
		cfg: TokenConfig{
			TokenName: string(EdgeAuthToken),
			Key:       key,
			Algorithm: SHA256,
		},
	}
}

// NewTokenBuilder creates a builder with a custom token name.
func NewTokenBuilder(key, tokenName string) *TokenBuilder {
	return &TokenBuilder{
		cfg: TokenConfig{
			TokenName: tokenName,
			Key:       key,
			Algorithm: SHA256,
		},
	}
}

// Algorithm sets the HMAC algorithm. Default is SHA256.
func (b *TokenBuilder) Algorithm(algo Algorithm) *TokenBuilder {
	b.cfg.Algorithm = algo
	return b
}

// Salt sets the additional salt secret (hex-encoded).
func (b *TokenBuilder) Salt(salt string) *TokenBuilder {
	b.cfg.Salt = salt
	return b
}

// IP restricts the token to a specific IP address.
func (b *TokenBuilder) IP(ip string) *TokenBuilder {
	b.cfg.IP = ip
	return b
}

// StartTime sets the token validity start as epoch seconds.
// If not called, defaults to the current time at generation.
func (b *TokenBuilder) StartTime(epoch int64) *TokenBuilder {
	b.cfg.StartTime = epoch
	return b
}

// EndTime sets the token expiration as epoch seconds.
// Mutually exclusive with WindowSeconds.
func (b *TokenBuilder) EndTime(epoch int64) *TokenBuilder {
	b.cfg.EndTime = epoch
	return b
}

// WindowSeconds sets the token TTL in seconds from StartTime.
// Mutually exclusive with EndTime.
func (b *TokenBuilder) WindowSeconds(seconds int64) *TokenBuilder {
	b.cfg.WindowSeconds = seconds
	return b
}

// ACL sets an explicit Access Control List path (supports wildcards *, ?).
// Multiple paths can be delimited with "!" (the default ACL delimiter).
// If set, this takes precedence over URL-derived ACL even when IsACL is true.
func (b *TokenBuilder) ACL(acl string) *TokenBuilder {
	b.cfg.ACL = acl
	return b
}

// ACLPaths sets an explicit Access Control List from multiple paths, joining
// them with the ACL delimiter. Takes precedence over URL-derived ACL.
func (b *TokenBuilder) ACLPaths(paths ...string) *TokenBuilder {
	delim := b.cfg.ACLDelimiter
	if delim == "" {
		delim = "!"
	}
	b.cfg.ACL = joinPaths(paths, delim)
	return b
}

// URL sets the content URL path. This is the primary required field.
// When IsACL is true, the directory portion is extracted and used as an
// ACL with a wildcard. When IsACL is false, the URL is used for URL-based
// token validation (hashed but not exposed in the token body).
func (b *TokenBuilder) URL(u string) *TokenBuilder {
	b.cfg.URL = u
	return b
}

// IsACL enables ACL extraction from the URL. When true, the directory
// portion of the URL is extracted and suffixed with "/*" to form the ACL.
// For example "/live/stream/master.m3u8" becomes "/live/stream/*".
func (b *TokenBuilder) IsACL(enabled bool) *TokenBuilder {
	b.cfg.IsACL = enabled
	return b
}

// SessionID sets the session identifier (max 64 bytes, printable ASCII).
func (b *TokenBuilder) SessionID(id string) *TokenBuilder {
	b.cfg.SessionID = id
	return b
}

// Payload sets additional data included in the token digest.
func (b *TokenBuilder) Payload(payload string) *TokenBuilder {
	b.cfg.Payload = payload
	return b
}

// DeviceID restricts playback to a specific device.
func (b *TokenBuilder) DeviceID(deviceID string) *TokenBuilder {
	b.cfg.DeviceID = deviceID
	return b
}

// UserAgent restricts playback to a specific User-Agent string.
func (b *TokenBuilder) UserAgent(ua string) *TokenBuilder {
	b.cfg.UserAgent = ua
	return b
}

// EscapeEarly enables URL-encoding of token field values.
func (b *TokenBuilder) EscapeEarly(escape bool) *TokenBuilder {
	b.cfg.EscapeEarly = escape
	return b
}

// FieldDelimiter sets the field delimiter character. Default is "~".
func (b *TokenBuilder) FieldDelimiter(delim string) *TokenBuilder {
	b.cfg.FieldDelimiter = delim
	return b
}

// ACLDelimiter sets the ACL path delimiter character. Default is "!".
func (b *TokenBuilder) ACLDelimiter(delim string) *TokenBuilder {
	b.cfg.ACLDelimiter = delim
	return b
}

// Config returns the current TokenConfig. Useful if you want to
// inspect or pass it elsewhere.
func (b *TokenBuilder) Config() TokenConfig {
	return b.cfg
}

// Generate produces the token string (without the token name prefix).
func (b *TokenBuilder) Generate() (string, error) {
	return Generate(b.cfg)
}

// GenerateWithName produces the full token string with the token name
// prefix (e.g. "hdnts=st=...~exp=...~acl=...~hmac=...").
func (b *TokenBuilder) GenerateWithName() (string, error) {
	return GenerateWithTokenName(b.cfg)
}

// joinPaths combines multiple path strings with a delimiter.
func joinPaths(paths []string, delim string) string {
	var sb strings.Builder
	for i, p := range paths {
		if i > 0 {
			sb.WriteString(delim)
		}
		sb.WriteString(p)
	}
	return sb.String()
}

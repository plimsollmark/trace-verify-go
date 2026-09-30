// Package uri checks that a string is an absolute URI in the RFC 3986 sense (section
// 4.3): a scheme, a colon, and the rest drawn only from the characters RFC 3986 section
// 2 allows, with every '%' starting a two-digit hex escape. Whitespace, control
// characters and non-ASCII characters are refused: a URI carrying them is a
// transcription accident, not an identifier (the suite's TR-APR-002 and TR-POL-003).
package uri

import "fmt"

// Absolute returns nil if s is an absolute URI.
func Absolute(s string) error {
	colon := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			colon = i
			break
		}
	}
	if colon < 1 {
		return fmt.Errorf("%q has no scheme", s)
	}
	for i := 0; i < colon; i++ { // scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
		c := s[i]
		alpha := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !alpha && (i == 0 || !(c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.')) {
			return fmt.Errorf("%q has an invalid scheme", s)
		}
	}
	for i := colon + 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%':
			if i+2 >= len(s) || !hex(s[i+1]) || !hex(s[i+2]) {
				return fmt.Errorf("%q has a malformed percent-escape", s)
			}
			i += 2
		case allowed(c):
		default:
			return fmt.Errorf("%q contains %q, which a URI may not carry unescaped", s, c)
		}
	}
	return nil
}

// HTTPSWithHost reports whether s is an absolute https URI with a non-empty authority
// host (the suite's TR-ANC-001 and TR-RTE-003 read "https://" literally).
func HTTPSWithHost(s string) error {
	if err := Absolute(s); err != nil {
		return err
	}
	const p = "https://"
	if len(s) <= len(p) || s[:len(p)] != p {
		return fmt.Errorf("%q is not an https:// URI", s)
	}
	host := s[len(p):]
	for i := 0; i < len(host); i++ {
		if host[i] == '/' || host[i] == '?' || host[i] == '#' {
			host = host[:i]
			break
		}
	}
	if at := lastIndex(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	if host == "" || host[0] == ':' {
		return fmt.Errorf("%q has no host", s)
	}
	return nil
}

func lastIndex(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func hex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// allowed is RFC 3986 unreserved plus reserved (gen-delims and sub-delims).
func allowed(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '-', '.', '_', '~', // unreserved
		':', '/', '?', '#', '[', ']', '@', // gen-delims
		'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=': // sub-delims
		return true
	}
	return false
}

package jcs

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonicalize parses data strictly and returns its RFC 8785 canonical bytes.
func Canonicalize(data []byte) ([]byte, error) {
	v, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return Encode(v)
}

// Encode serializes a parsed value in the RFC 8785 canonical form.
func Encode(v any) ([]byte, error) {
	return appendValue(nil, v)
}

// ErrUnsupported is returned by Encode for a Go value that is not a parsed JSON value.
var ErrUnsupported = errors.New("jcs: not a parsed JSON value")

func appendValue(b []byte, v any) ([]byte, error) {
	switch v := v.(type) {
	case nil:
		return append(b, "null"...), nil
	case bool:
		if v {
			return append(b, "true"...), nil
		}
		return append(b, "false"...), nil
	case string:
		return appendString(b, v)
	case Number:
		s, err := FormatNumber(v.Float)
		if err != nil {
			return nil, err
		}
		return append(b, s...), nil
	case []any:
		b = append(b, '[')
		for i, e := range v {
			if i > 0 {
				b = append(b, ',')
			}
			var err error
			if b, err = appendValue(b, e); err != nil {
				return nil, err
			}
		}
		return append(b, ']'), nil
	case *Object:
		// RFC 8785 section 3.2.3: members sorted by their names as UTF-16 code units.
		ms := slices.Clone(v.Members)
		slices.SortFunc(ms, func(a, b Member) int { return compareUTF16(a.Name, b.Name) })
		b = append(b, '{')
		for i, m := range ms {
			if i > 0 {
				b = append(b, ',')
			}
			var err error
			if b, err = appendString(b, m.Name); err != nil {
				return nil, err
			}
			b = append(b, ':')
			if b, err = appendValue(b, m.Value); err != nil {
				return nil, err
			}
		}
		return append(b, '}'), nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupported, v)
	}
}

// appendString follows RFC 8785 section 3.2.2.2: only '"', '\\' and U+0000 to U+001F
// are escaped, the five with short forms by those forms and the rest as lowercase
// \u00hh. Every other character, U+007F and U+2028 included, is written as UTF-8.
func appendString(b []byte, s string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, ErrInvalidUTF8 // a parsed string is always valid; a built one may not be
	}
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b = append(b, '\\', '"')
		case c == '\\':
			b = append(b, '\\', '\\')
		case c == '\b':
			b = append(b, '\\', 'b')
		case c == '\t':
			b = append(b, '\\', 't')
		case c == '\n':
			b = append(b, '\\', 'n')
		case c == '\f':
			b = append(b, '\\', 'f')
		case c == '\r':
			b = append(b, '\\', 'r')
		case c < 0x20:
			b = append(b, '\\', 'u', '0', '0', "0123456789abcdef"[c>>4], "0123456789abcdef"[c&0xf])
		default:
			b = append(b, c)
		}
	}
	return append(b, '"'), nil
}

// compareUTF16 orders two strings by their UTF-16 code units, which is not code-point
// order: a supplementary-plane character becomes a surrogate pair (U+D800 to U+DFFF)
// and so sorts below U+E000 to U+FFFF.
func compareUTF16(a, b string) int {
	for a != "" && b != "" {
		ra, na := utf8.DecodeRuneInString(a)
		rb, nb := utf8.DecodeRuneInString(b)
		if ra != rb {
			return slices.Compare(units(ra), units(rb))
		}
		a, b = a[na:], b[nb:]
	}
	return len(a) - len(b) // only the sign is used; the shorter string sorts first
}

func units(r rune) []uint16 {
	if r >= 0x10000 {
		hi, lo := utf16.EncodeRune(r)
		return []uint16{uint16(hi), uint16(lo)}
	}
	return []uint16{uint16(r)}
}

// FormatNumber writes a double as ECMA-262 section 7.1.12.1 (Number::toString) does,
// which RFC 8785 section 3.2.2.3 adopts: the shortest digits that round-trip, laid out
// in positional form for decimal exponents from -6 to 21 and in exponent form outside.
func FormatNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", ErrNonFinite
	}
	if f == 0 { // both zeros
		return "0", nil
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	// Go's shortest 'e' form gives the digit string s (k digits) and the exponent,
	// from which ECMA-262's n is exponent + 1.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, exp, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, err := strconv.Atoi(exp)
	if err != nil {
		return "", err
	}
	k, n := len(digits), x+1
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		es := "+"
		if n-1 < 0 {
			es = "-"
		}
		out = digits[:1]
		if k > 1 {
			out += "." + digits[1:]
		}
		out += "e" + es + strconv.Itoa(abs(n-1))
	}
	return sign + out, nil
}

func abs(i int) int {
	if i < 0 {
		return -i
	}
	return i
}

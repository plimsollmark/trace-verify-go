package jcs

import (
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

// RFC 8785 Appendix B, every row.
func TestNumberSamplesFromRFC8785AppendixB(t *testing.T) {
	cases := []struct{ bits, want string }{
		{"0000000000000000", "0"},
		{"8000000000000000", "0"},
		{"0000000000000001", "5e-324"},
		{"8000000000000001", "-5e-324"},
		{"7fefffffffffffff", "1.7976931348623157e+308"},
		{"ffefffffffffffff", "-1.7976931348623157e+308"},
		{"4340000000000000", "9007199254740992"},
		{"c340000000000000", "-9007199254740992"},
		{"4430000000000000", "295147905179352830000"},
		{"44b52d02c7e14af5", "9.999999999999997e+22"},
		{"44b52d02c7e14af6", "1e+23"},
		{"44b52d02c7e14af7", "1.0000000000000001e+23"},
		{"444b1ae4d6e2ef4e", "999999999999999700000"},
		{"444b1ae4d6e2ef4f", "999999999999999900000"},
		{"444b1ae4d6e2ef50", "1e+21"},
		{"3eb0c6f7a0b5ed8c", "9.999999999999997e-7"},
		{"3eb0c6f7a0b5ed8d", "0.000001"},
		{"41b3de4355555553", "333333333.3333332"},
		{"41b3de4355555554", "333333333.33333325"},
		{"41b3de4355555555", "333333333.3333333"},
		{"41b3de4355555556", "333333333.3333334"},
		{"41b3de4355555557", "333333333.33333343"},
		{"becbf647612f3696", "-0.0000033333333333333333"},
		{"43143ff3c1cb0959", "1424953923781206.2"},
	}
	for _, c := range cases {
		u, err := strconv.ParseUint(c.bits, 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		got, err := FormatNumber(math.Float64frombits(u))
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.bits, got, err, c.want)
		}
	}
	for _, bits := range []uint64{0x7fffffffffffffff, 0x7ff0000000000000} {
		if _, err := FormatNumber(math.Float64frombits(bits)); !errors.Is(err, ErrNonFinite) {
			t.Errorf("%016x: got %v, want ErrNonFinite", bits, err)
		}
	}
}

// RFC 8785 sections 3.2.2 and 3.2.4: the sample object and its canonical bytes.
func TestSampleObjectFromRFC8785(t *testing.T) {
	in := `{
       "numbers": [333333333.33333329, 1E30, 4.50,
                   2e-3, 0.000000000000000000000000001],
       "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
       "literals": [null, true, false]
     }`
	want, err := hex.DecodeString(strings.Join(strings.Fields(`
     7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72
     75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a
     5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31
     65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37
     5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30
     30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d`), ""))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Canonicalize([]byte(in))
	if err != nil || string(got) != string(want) {
		t.Fatalf("got %s, %v\nwant %s", got, err, want)
	}
}

// RFC 8785 section 3.2.3: the sorting sample, whose order differs from code-point order.
func TestSortingSampleFromRFC8785(t *testing.T) {
	in := `{
       "\u20ac": "Euro Sign",
       "\r": "Carriage Return",
       "\ufb33": "Hebrew Letter Dalet With Dagesh",
       "1": "One",
       "\ud83d\ude00": "Emoji: Grinning Face",
       "\u0080": "Control",
       "\u00f6": "Latin Small Letter O With Diaeresis"
     }`
	v, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	sorted, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range sorted.(*Object).Members {
		got = append(got, m.Value.(string))
	}
	want := []string{"Carriage Return", "One", "Control", "Latin Small Letter O With Diaeresis",
		"Euro Sign", "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("order %q, want %q", got, want)
	}
}

func TestStrictParserRefusals(t *testing.T) {
	cases := []struct {
		name, in string
		want     error
	}{
		{"duplicate name", `{"a":1,"a":2}`, ErrDuplicateName},
		{"duplicate after unescaping", `{"a":1,"\u0061":2}`, ErrDuplicateName},
		{"lone high surrogate", `"\ud800"`, ErrLoneSurrogate},
		{"lone low surrogate", `"\udc00"`, ErrLoneSurrogate},
		{"high then non-low", `"\ud800A"`, ErrLoneSurrogate},
		{"high then text", `"\ud800x"`, ErrLoneSurrogate},
		{"invalid UTF-8", "\"\xff\"", ErrInvalidUTF8},
		{"UTF-8 encoded surrogate", "\"\xed\xa0\x80\"", ErrInvalidUTF8},
		{"overlong UTF-8", "\"\xc0\xaf\"", ErrInvalidUTF8},
		{"raw control character", "\"a\x01\"", ErrSyntax},
		{"number overflows the double", `1e400`, ErrNonFinite},
		{"negative overflow", `-1e400`, ErrNonFinite},
		{"leading zero", `01`, ErrSyntax},
		{"bare decimal point", `1.`, ErrSyntax},
		{"leading decimal point", `.5`, ErrSyntax},
		{"plus sign", `+1`, ErrSyntax},
		{"empty exponent", `1e`, ErrSyntax},
		{"byte order mark", "\xef\xbb\xbf{}", ErrSyntax},
		{"trailing data", `{} {}`, ErrSyntax},
		{"trailing comma", `[1,]`, ErrSyntax},
		{"NaN literal", `NaN`, ErrSyntax},
		{"single quotes", `'a'`, ErrSyntax},
		{"too deep", strings.Repeat("[", MaxDepth+2) + strings.Repeat("]", MaxDepth+2), ErrTooDeep},
	}
	for _, c := range cases {
		if _, err := Parse([]byte(c.in)); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestStringEscapes(t *testing.T) {
	cases := map[string]string{
		`"\u0000\u001f\u007f"`:     `"\u0000\u001f` + "\x7f" + `"`,
		`"\b\t\n\f\r"`:             `"\b\t\n\f\r"`,
		`"\u2028\u2029"`:           "\"\u2028\u2029\"",
		`"\/"`:                     `"/"`,
		`"\ud83d\ude00"`:           "\"\U0001F600\"",
		"\"\U0001F600\"":           "\"\U0001F600\"",
		`"\u00e9"`:                 "\"\u00e9\"",
		`"a\"b\\c"`:                `"a\"b\\c"`,
		`{"b":[],"a":{},"c":null}`: `{"a":{},"b":[],"c":null}`,
	}
	for in, want := range cases {
		got, err := Canonicalize([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%s: got %s, %v; want %s", in, got, err, want)
		}
	}
}

func TestUnderflowIsZero(t *testing.T) {
	// A literal below the smallest subnormal denotes the double 0 (RFC 8785 serializes
	// the double, not the literal).
	got, err := Canonicalize([]byte(`[1e-400,-1e-400,0.0,-0]`))
	if err != nil || string(got) != `[0,0,0,0]` {
		t.Fatalf("got %s, %v", got, err)
	}
}

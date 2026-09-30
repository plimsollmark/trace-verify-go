package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/plimsollmark/trace-verify-go/jcs"
)

func parse(t *testing.T, s string) (*Key, error) {
	t.Helper()
	v, err := jcs.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return Parse(v)
}

// RFC 8037 Appendix A.2 to A.5.
const rfc8037Public = `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

func TestRFC8037Thumbprint(t *testing.T) {
	k, err := parse(t, rfc8037Public)
	if err != nil {
		t.Fatal(err)
	}
	if got := k.Thumbprint(); got != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("thumbprint %s", got)
	}
	// Optional members do not change it.
	k2, err := parse(t, `{"kid":"x","use":"sig","kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)
	if err != nil || k2.Thumbprint() != k.Thumbprint() {
		t.Fatalf("thumbprint with optional members: %v", err)
	}
}

func TestRFC8037Signature(t *testing.T) {
	k, err := parse(t, rfc8037Public)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc")
	sig, _ := hex.DecodeString(strings.Join(strings.Fields(`
	86 0c 98 d2 29 7f 30 60 a3 3f 42 73 96 72 d6 1b
	53 cf 3a de fe d3 d3 c6 72 f3 20 dc 02 1b 41 1e
	9d 59 b8 62 8d c3 51 e2 48 b8 8b 29 46 8e 0e 41
	85 5b 0f b7 d8 3b b1 5b e9 02 bf cc b8 cd 0a 02`), ""))
	if err := k.Verify(input, sig); err != nil {
		t.Fatal(err)
	}
	sig[10] ^= 1
	if err := k.Verify(input, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("flipped bit: %v", err)
	}
	if err := k.Verify(input, sig[:63]); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("short signature: %v", err)
	}
}

func TestRefusals(t *testing.T) {
	cases := []struct {
		name, jwk string
		want      error
	}{
		{"RFC 8037 A.1 private key", `{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`, ErrPrivate},
		{"symmetric key", `{"kty":"oct","k":"AAAA"}`, ErrPrivate},
		{"RSA private factor", `{"kty":"RSA","n":"AQAB","e":"AQAB","qi":"AA"}`, ErrPrivate},
		{"kty absent", `{"crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`, ErrNoKeyType},
		{"kty not a string", `{"kty":1}`, ErrNoKeyType},
		{"RSA", `{"kty":"RSA","n":"AQAB","e":"AQAB"}`, ErrUnsupported},
		{"X25519", `{"kty":"OKP","crv":"X25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`, ErrUnsupported},
		{"P-521", `{"kty":"EC","crv":"P-521","x":"AA","y":"AA"}`, ErrUnsupported},
		{"x padded", `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo="}`, ErrMalformed},
		{"x short", `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHUR"}`, ErrMalformed},
		{"x absent", `{"kty":"OKP","crv":"Ed25519"}`, ErrMalformed},
		{"EC point off the curve", `{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}`, ErrMalformed},
	}
	for _, c := range cases {
		if _, err := parse(t, c.jwk); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := Parse("not an object"); !errors.Is(err, ErrNotObject) {
		t.Errorf("non-object: %v", err)
	}
}

func TestECRawSignatures(t *testing.T) {
	for _, c := range []struct {
		curve elliptic.Curve
		name  string
		size  int
	}{{elliptic.P256(), "P-256", 32}, {elliptic.P384(), "P-384", 48}} {
		priv, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := priv.PublicKey.Bytes() // 0x04 || X || Y
		if err != nil {
			t.Fatal(err)
		}
		k, err := parse(t, fmt.Sprintf(`{"kty":"EC","crv":%q,"x":%q,"y":%q}`, c.name,
			B64.EncodeToString(raw[1:1+c.size]), B64.EncodeToString(raw[1+c.size:])))
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("canonical record bytes")
		var digest []byte
		if c.size == 32 {
			d := sha256.Sum256(msg)
			digest = d[:]
		} else {
			d := sha512.Sum384(msg)
			digest = d[:]
		}
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, 2*c.size)
		r.FillBytes(sig[:c.size])
		s.FillBytes(sig[c.size:])
		if err := k.Verify(msg, sig); err != nil {
			t.Fatalf("%s raw r||s: %v", c.name, err)
		}
		der, err := ecdsa.SignASN1(rand.Reader, priv, digest)
		if err != nil {
			t.Fatal(err)
		}
		if err := k.Verify(msg, der); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("%s DER signature: %v, want ErrBadSignature", c.name, err)
		}
	}
}

package uri

import "testing"

func TestAbsolute(t *testing.T) {
	good := []string{"https://verifier.example.org", "https://policies.example.org/appraisal/v3",
		"urn:ietf:rfc:3986", "did:web:example.org", "spiffe://trust.example/agent/x", "https://h/p%20q"}
	bad := []string{"", "./policies/v1", "nvidia-openshell/0.3.0", "ht tp://x", "https://h/p q",
		"https://h/\x01", "https://h/é", "1https://h", ":nothing", "https://h/%zz", "https://h/%2"}
	for _, s := range good {
		if err := Absolute(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range bad {
		if Absolute(s) == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestHTTPSWithHost(t *testing.T) {
	good := []string{"https://transparency.example/entries/abc123", "https://h", "https://user@h:443/x"}
	bad := []string{"http://h/x", "https://", "https:///path", "ipfs://x", "/bare/path", "https://:443/x"}
	for _, s := range good {
		if err := HTTPSWithHost(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range bad {
		if HTTPSWithHost(s) == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

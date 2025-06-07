package main

import (
	"testing"

	oauthjwt "github.com/nitsugaro/oauth-jwt"
)

func TestInvalidJwt(t *testing.T) {
	jwt := "eyJhbGciOiJIUzUxMiIsImtpZCI6IldDb3hVdnIxeTRPbEt5VU1VcmpYNVEiLCJ0eXBlIjoiSldUIn0.eyJpc3MiOiJURVNUIiwic3ViIjoiMTIzNCJ9.VMINjihMGzkuYXlfA9xYZ8Ka1DU6eO-MJWKnWaTOraJa1pZyyFvXM-chtmuROe4JS_pKjJA1x0OzltIjboc6sA"

	parsedJwt, err := oauthjwt.ParseJwt(jwt)
	if err != nil {
		t.Errorf("expected for invalid jwt be parsed correctly")
	}

	if jmHmac64.Verify(parsedJwt) {
		t.Errorf("expected jwt must be invalid WT*!")
	}
}

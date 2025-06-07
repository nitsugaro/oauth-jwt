package oauthjwt

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
)

func Base64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

/* Generates randon bytes with 'n' length and encode to standard base64url */
func RandomBytesBase64Url(n int) string {
	bytes := make([]byte, n)

	rand.Read(bytes)

	return base64.RawURLEncoding.EncodeToString(bytes)
}

/* Generates randon bytes with 'n' length and encode to standard base64 */
func RandomBytesBase64(n int) string {
	bytes := make([]byte, n)

	rand.Read(bytes)

	return base64.StdEncoding.EncodeToString(bytes)
}

/*
supported jwt algs: HS, RS, ES.
supported algs: SHA-256, SHA-384, SHA-512
*/
func HashByJwtAlg(content []byte, jwtAlg ALG) ([]byte, error) {
	switch jwtAlg {
	case HS256, RS256, ES256:
		h := sha256.New()
		h.Write(content)
		return h.Sum(nil), nil
	case HS384, RS384, ES384:
		h := sha512.New384()
		h.Write(content)
		return h.Sum(nil), nil
	case HS512, RS512, ES512:
		h := sha512.New()
		h.Write(content)
		return h.Sum(nil), nil
	default:
		return nil, ErrInvalidShaAlg
	}
}

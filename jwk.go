package oauthjwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"math/big"
	"strings"
)

var cacheJwks []JWK

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	N   string `json:"n,omitempty"` // RSA modulus
	E   string `json:"e,omitempty"` // RSA exponent
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"` // EC x
	Y   string `json:"y,omitempty"` // EC y
}

func b64urlBigInt(n *big.Int) string {
	return Base64url(n.Bytes())
}

func (jm *JwtManager) GetPublicJWKs() []JWK {
	if cacheJwks != nil {
		return cacheJwks
	}

	var jwks []JWK

	for _, k := range jm.keys {
		kty := strings.Split(k.kty, "-")[0]
		switch kty {
		case "RSA":
			priv := k.value.(*rsa.PrivateKey)

			pub := priv.PublicKey
			jwks = append(jwks, JWK{
				Kid: k.kid,
				Kty: kty,
				Use: "sig",
				N:   b64urlBigInt(pub.N),
				E:   b64urlBigInt(big.NewInt(int64(pub.E))),
			})

		case "EC":
			priv := k.value.(*ecdsa.PrivateKey)
			pub := priv.PublicKey
			crv := ""
			alg := ""
			bitSize := pub.Curve.Params().BitSize
			switch bitSize {
			case 256:
				crv = "P-256"
				alg = string(ES256)
			case 384:
				crv = "P-384"
				alg = string(ES384)
			case 521:
				crv = "P-521"
				alg = string(ES512)
			}
			jwks = append(jwks, JWK{
				Kid: k.kid,
				Kty: kty,
				Alg: alg,
				Use: "sig",
				Crv: crv,
				X:   b64urlBigInt(pub.X),
				Y:   b64urlBigInt(pub.Y),
			})
		}
	}

	cacheJwks = jwks

	return jwks
}

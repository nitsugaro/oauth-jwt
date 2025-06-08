package oauthjwt

import (
	"slices"
	"strings"
)

type JwtBuilder struct {
	*jwtHeader
	*jwtClaims
}

func (jm *JwtManager) NewBuilder() *JwtBuilder {
	jwtBuilder := &JwtBuilder{
		jwtHeader: &jwtHeader{&jwtPart{}},
		jwtClaims: &jwtClaims{&jwtPart{}},
	}

	jwtBuilder.SetType("JWT")
	jwtBuilder.SetIss(jm.GetIss())

	return jwtBuilder
}

type Jwt struct {
	*jwtHeader
	*jwtClaims
	headerBase64Url string
	claimsBase64Url string
	signature       string
}

func (jwt *Jwt) GetHeaderB64Url() string {
	return jwt.headerBase64Url
}

func (jwt *Jwt) GetClaimsB64Url() string {
	return jwt.claimsBase64Url
}

func (jwt *Jwt) GetSignature() string {
	return jwt.signature
}

func (jwt *Jwt) GetContentForSign() []byte {
	return []byte(jwt.headerBase64Url + "." + jwt.claimsBase64Url)
}

func (jm *JwtManager) Verify(jwt *Jwt) bool {
	alg := jwt.GetAlg()

	if !slices.Contains(SUPPORTED_ALGORITHMS, alg) {
		return false
	}

	algStr := string(alg)
	if strings.HasPrefix(algStr, "HS") {
		return jm.verifyHmac(jwt)
	} else if strings.HasPrefix(algStr, "RS") {
		return jm.verifyRsa(jwt)
	} else {
		return jm.verifyEc(jwt)
	}
}

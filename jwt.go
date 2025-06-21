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

func (jm *JwtManager) NewBuilderFromJwt(jwt IJwt) *JwtBuilder {
	return &JwtBuilder{
		jwtHeader: jwt.GetHeaders(),
		jwtClaims: jwt.GetClaims(),
	}
}

type IJwt interface {
	IJwtHeader
	IJwtClaims

	GetHeaderB64Url() string
	GetClaimsB64Url() string
	GetSignature() string
	GetContentForSign() []byte
	GetHeaders() *jwtHeader
	GetClaims() *jwtClaims
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

func (jwt *Jwt) GetHeaders() *jwtHeader {
	return jwt.jwtHeader
}

func (jwt *Jwt) GetClaims() *jwtClaims {
	return jwt.jwtClaims
}

func (jm *JwtManager) Sign(jwtBuilder *JwtBuilder) (string, error) {
	switch jwtBuilder.GetAlg() {
	case HS256:
		return jm.SignHmac(jwtBuilder, HS256_ALG, nil)
	case HS384:
		return jm.SignHmac(jwtBuilder, HS384_ALG, nil)
	case HS512:
		return jm.SignHmac(jwtBuilder, HS512_ALG, nil)
	case RS256:
		return jm.SignRsa(jwtBuilder, RS256_ALG, nil)
	case RS384:
		return jm.SignRsa(jwtBuilder, RS384_ALG, nil)
	case RS512:
		return jm.SignRsa(jwtBuilder, RS512_ALG, nil)
	case ES256:
		return jm.SignEc(jwtBuilder, ES256_ALG, nil)
	case ES384:
		return jm.SignEc(jwtBuilder, ES384_ALG, nil)
	case ES512:
		return jm.SignEc(jwtBuilder, ES512_ALG, nil)
	default:
		return "", ErrInvalidAlgHeaderJwt
	}
}

func (jm *JwtManager) Verify(jwt IJwt) bool {
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

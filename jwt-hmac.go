package oauthjwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
)

func HmacHash(content []byte, secret []byte, alg HS_ALG) ([]byte, error) {
	var signature []byte
	if alg == HS256_ALG {
		mac256 := hmac.New(sha256.New, secret)
		mac256.Write(content)
		signature = mac256.Sum(nil)
	} else if alg == HS384_ALG {
		mac384 := hmac.New(sha512.New384, secret)
		mac384.Write(content)
		signature = mac384.Sum(nil)
	} else if alg == HS512_ALG {
		mac512 := hmac.New(sha512.New, secret)
		mac512.Write(content)
		signature = mac512.Sum(nil)
	} else {
		return nil, ErrInvalidAlgHeaderJwt
	}

	return signature, nil
}

func (jm *JwtManager) SignHmac(jwtBuilder *JwtBuilder, alg HS_ALG, secretKey *Key) (string, error) {
	jwtHeader := jwtBuilder.jwtHeader
	jwtClaims := jwtBuilder.jwtClaims

	if secretKey == nil {
		secretKey = jm.GetKeyForSignSecret()
	}

	jwtHeader.SetAlg(ALG(alg))
	jwtHeader.SetKid(secretKey.kid)

	headerBase64Url, err := jwtHeader.EncodeBase64Url()
	if err != nil {
		return "", err
	}
	claimsBase64Url, err := jwtClaims.EncodeBase64Url()
	if err != nil {
		return "", err
	}

	var content = []byte(headerBase64Url + "." + claimsBase64Url)
	secret, err := base64.StdEncoding.DecodeString(secretKey.value.(string))
	if err != nil {
		return "", err
	}

	signature, err := HmacHash(content, secret, HS_ALG(alg))
	if err != nil {
		return "", err
	}

	jwt := headerBase64Url + "." + claimsBase64Url + "." + base64.RawURLEncoding.EncodeToString(signature)

	return jwt, nil
}

func (jm *JwtManager) verifyHmac(jwt *Jwt) bool {
	kid := jwt.GetKid()
	secretKey := jm.GetKey(kid)
	if secretKey == nil {
		return false
	}

	secret, _ := base64.StdEncoding.DecodeString(secretKey.value.(string))
	signature, err := HmacHash(jwt.GetContentForSign(), secret, HS_ALG(jwt.GetAlg()))
	if err != nil {
		return false
	}

	return base64.RawURLEncoding.EncodeToString(signature) == jwt.signature
}

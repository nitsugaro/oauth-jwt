package oauthjwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
)

func getShaAlg(alg RS_ALG) crypto.Hash {
	switch alg {
	case RS256_ALG:
		return crypto.SHA256
	case RS384_ALG:
		return crypto.SHA384
	default:
		return crypto.SHA512
	}
}

func (jm *JwtManager) SignRsa(jwtBuilder *JwtBuilder, alg RS_ALG, rsaKey *Key) (string, error) {
	jwtHeader := jwtBuilder.jwtHeader
	jwtClaims := jwtBuilder.jwtClaims

	if rsaKey == nil {
		rsaKey = jm.GetKeyForSignRsa()
	}

	jwtHeader.SetAlg(ALG(alg))
	jwtHeader.SetKid(rsaKey.kid)

	headerBase64Url, err := jwtHeader.EncodeBase64Url()
	if err != nil {
		return "", err
	}
	claimsBase64Url, err := jwtClaims.EncodeBase64Url()
	if err != nil {
		return "", err
	}

	var content = []byte(headerBase64Url + "." + claimsBase64Url)

	hashed, err := HashByJwtAlg(content, ALG(alg))
	if err != nil {
		return "", err
	}

	privateKey := rsaKey.value.(*rsa.PrivateKey)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, getShaAlg(alg), hashed[:])
	if err != nil {
		return "", err
	}

	jwt := headerBase64Url + "." + claimsBase64Url + "." + base64.RawURLEncoding.EncodeToString(signature)
	return jwt, nil
}

func (jm *JwtManager) verifyRsa(jwt IJwt) bool {
	kid := jwt.GetKid()
	rsaKey := jm.GetKey(kid)
	if rsaKey == nil {
		return false
	}

	hashed, err := HashByJwtAlg(jwt.GetContentForSign(), jwt.GetAlg())
	if err != nil {
		return false
	}

	signature, err := base64.RawURLEncoding.DecodeString(jwt.GetSignature())
	if err != nil {
		return false
	}

	privateKey := rsaKey.value.(*rsa.PrivateKey)
	shaAlg := getShaAlg(RS_ALG(jwt.GetAlg()))
	return rsa.VerifyPKCS1v15(&privateKey.PublicKey, shaAlg, hashed[:], signature) == nil
}

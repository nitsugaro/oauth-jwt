package oauthjwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

func intToFixedBytes(i *big.Int, size int) []byte {
	b := i.Bytes()
	if len(b) > size {
		return b[len(b)-size:]
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

func (jm *JwtManager) SignEc(jwtBuilder *JwtBuilder, alg ES_ALG) (string, error) {
	jwtHeader := jwtBuilder.jwtHeader
	jwtClaims := jwtBuilder.jwtClaims
	ecKey := jm.GetKeyForSignEc(alg)

	jwtHeader.SetAlg(ALG(alg))
	jwtHeader.SetKid(ecKey.kid)

	headerBase64Url, err := jwtHeader.EncodeBase64Url()
	if err != nil {
		return "", err
	}
	claimsBase64Url, err := jwtClaims.EncodeBase64Url()
	if err != nil {
		return "", err
	}

	content := []byte(headerBase64Url + "." + claimsBase64Url)

	hashed, err := HashByJwtAlg(content, ALG(alg))
	if err != nil {
		return "", err
	}

	privateKey := ecKey.value.(*ecdsa.PrivateKey)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	if err != nil {
		return "", err
	}

	keyBytesLen := (privateKey.Params().BitSize + 7) / 8

	rBytes := r.Bytes()
	sBytes := s.Bytes()
	paddedR := intToFixedBytes(r, keyBytesLen)
	paddedS := intToFixedBytes(s, keyBytesLen)
	copy(paddedR[keyBytesLen-len(rBytes):], rBytes)
	copy(paddedS[keyBytesLen-len(sBytes):], sBytes)

	signatureBytes := append(paddedR, paddedS...)

	jwt := headerBase64Url + "." + claimsBase64Url + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	return jwt, nil
}

func (jm *JwtManager) verifyEc(jwt *Jwt) bool {
	kid := jwt.GetKid()
	ecKey := jm.GetKey(kid)
	if ecKey == nil {
		return false
	}

	hashed, err := HashByJwtAlg(jwt.GetContentForSign(), jwt.GetAlg())
	if err != nil {
		return false
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(jwt.signature)
	if err != nil {
		return false
	}

	pubKey := ecKey.value.(*ecdsa.PrivateKey).PublicKey
	keyBytesLen := (pubKey.Params().BitSize + 7) / 8

	if len(signatureBytes) != keyBytesLen*2 {
		return false
	}

	r := new(big.Int).SetBytes(signatureBytes[:keyBytesLen])
	s := new(big.Int).SetBytes(signatureBytes[keyBytesLen:])

	privateKey := ecKey.value.(*ecdsa.PrivateKey)

	return ecdsa.Verify(&privateKey.PublicKey, hashed[:], r, s)
}

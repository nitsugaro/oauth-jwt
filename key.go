package oauthjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strconv"
	"strings"
	"time"
)

type Key struct {
	kid   string
	kty   string
	param string
	iat   int64
	value interface{}
}

func (k *Key) GetKid() string {
	return k.kid
}

func (k *Key) GetKty() string {
	return strings.Split(k.kty, "-")[0]
}

func (k *Key) GetIat() int64 {
	return k.iat
}

func GenerateSecretKey(n SECRET_BITS) (*Key, error) {
	if n != SECRET_32 && n != SECRET_64 {
		return nil, ErrSecretKeyLength
	}

	return &Key{
		kid:   RandomBytesBase64Url(KID_LENGTH),
		kty:   SECRET_KTY,
		param: strconv.Itoa(int(n)),
		value: RandomBytesBase64(int(n)),
		iat:   time.Now().Unix(),
	}, nil
}

func GenerateRsaKey(n RSA_BITS) (*Key, error) {
	if n != RSA_2048 && n != RSA_3072 && n != RSA_4096 {
		return nil, ErrRsaKeyBits
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, int(n))
	if err != nil {
		return nil, err
	}

	return &Key{
		kid:   RandomBytesBase64Url(KID_LENGTH),
		kty:   RSA_KTY,
		param: strconv.Itoa(int(n)),
		value: rsaKey,
		iat:   time.Now().Unix(),
	}, nil
}

func GenerateEcKey(jwtEsAlg ES_ALG) (*Key, error) {
	var crv elliptic.Curve
	switch jwtEsAlg {
	case ES256_ALG:
		crv = elliptic.P256()
	case ES384_ALG:
		crv = elliptic.P384()
	case ES512_ALG:
		crv = elliptic.P521()
	default:
		return nil, ErrEcKeyCrv
	}

	ecKey, err := ecdsa.GenerateKey(crv, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Key{
		kid:   RandomBytesBase64Url(KID_LENGTH),
		kty:   EC_KTY + "-" + string(jwtEsAlg),
		param: string(jwtEsAlg),
		value: ecKey,
		iat:   time.Now().Unix(),
	}, nil
}

func (jm *JwtManager) RegenerateKey(prevKey *Key) (*Key, error) {
	var key *Key
	kty := prevKey.GetKty()

	switch kty {
	case RSA_KTY:
		n, _ := strconv.Atoi(prevKey.param)
		key, _ = GenerateRsaKey(RSA_BITS(n))
	case SECRET_KTY:
		n, _ := strconv.Atoi(prevKey.param)
		key, _ = GenerateSecretKey(SECRET_BITS(n))
	case EC_KTY:
		key, _ = GenerateEcKey(ES_ALG(prevKey.param))
	default:
		return nil, ErrInvalidKeyTypeFile
	}

	jm.SetKey(key)

	return key, nil
}

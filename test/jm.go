package main

import oauthjwt "github.com/nitsugaro/oauth-jwt"

func getJmHmac32() *oauthjwt.JwtManager {
	jm := &oauthjwt.JwtManager{
		FolderPath:        "./keys/hs32-keys",
		Iss:               "TEST",
		KeyExpTimeMinutes: int64(1),
	}

	jm.ResetStorage()

	secret32, err := oauthjwt.GenerateSecretKey(oauthjwt.SECRET_32)
	if err != nil {
		panic(err)
	}

	jm.InitKeys(secret32)

	return jm
}

func getJmHmac64() *oauthjwt.JwtManager {
	jm := &oauthjwt.JwtManager{
		FolderPath:        "./keys/hs64-keys",
		Iss:               "TEST",
		KeyExpTimeMinutes: int64(1),
	}

	jm.ResetStorage()

	secret64, err := oauthjwt.GenerateSecretKey(oauthjwt.SECRET_64)
	if err != nil {
		panic(err)
	}

	jm.InitKeys(secret64)

	return jm
}

func getJmRsa2048() *oauthjwt.JwtManager {
	jm := &oauthjwt.JwtManager{
		FolderPath:        "./keys/rsa2048-keys",
		Iss:               "TEST",
		KeyExpTimeMinutes: int64(1),
	}

	jm.ResetStorage()

	rsa2048, err := oauthjwt.GenerateRsaKey(oauthjwt.RSA_2048)
	if err != nil {
		panic(err)
	}

	jm.InitKeys(rsa2048)

	return jm
}

func getJmRsa3072() *oauthjwt.JwtManager {
	jm := &oauthjwt.JwtManager{
		FolderPath:        "./keys/rsa3072-keys",
		Iss:               "TEST",
		KeyExpTimeMinutes: int64(1),
	}

	jm.ResetStorage()

	rsa3072, err := oauthjwt.GenerateRsaKey(oauthjwt.RSA_3072)
	if err != nil {
		panic(err)
	}

	jm.InitKeys(rsa3072)

	return jm
}

func getJmRsa4096() *oauthjwt.JwtManager {
	jm := &oauthjwt.JwtManager{
		FolderPath:        "./keys/rsa4096-keys",
		Iss:               "TEST",
		KeyExpTimeMinutes: int64(1),
	}

	jm.ResetStorage()

	rsa4096, err := oauthjwt.GenerateRsaKey(oauthjwt.RSA_4096)
	if err != nil {
		panic(err)
	}

	jm.InitKeys(rsa4096)

	return jm
}

func getJmEc256() *oauthjwt.JwtManager {
	jm := &oauthjwt.JwtManager{
		FolderPath:        "./keys/ec256-keys",
		Iss:               "TEST",
		KeyExpTimeMinutes: int64(1),
	}

	jm.ResetStorage()

	ec256, err := oauthjwt.GenerateEcKey(oauthjwt.ES256_ALG)
	if err != nil {
		panic(err)
	}

	jm.InitKeys(ec256)

	return jm
}

func getJmEc384() *oauthjwt.JwtManager {
	jm := &oauthjwt.JwtManager{
		FolderPath:        "./keys/ec384-keys",
		Iss:               "TEST",
		KeyExpTimeMinutes: int64(1),
	}

	jm.ResetStorage()

	ec384, err := oauthjwt.GenerateEcKey(oauthjwt.ES384_ALG)
	if err != nil {
		panic(err)
	}

	jm.InitKeys(ec384)

	return jm
}

func getJmEc512() *oauthjwt.JwtManager {
	jm := &oauthjwt.JwtManager{
		FolderPath:        "./keys/ec512-keys",
		Iss:               "TEST",
		KeyExpTimeMinutes: int64(1),
	}

	jm.ResetStorage()

	ec512, err := oauthjwt.GenerateEcKey(oauthjwt.ES512_ALG)
	if err != nil {
		panic(err)
	}

	jm.InitKeys(ec512)

	return jm
}

var jmHmac32 = getJmHmac32()
var jmHmac64 = getJmHmac64()
var jmRsa2048 = getJmRsa2048()
var jmRsa3072 = getJmRsa3072()
var jmRsa4096 = getJmRsa4096()
var jmEc256 = getJmEc256()
var jmEc384 = getJmEc384()
var jmEc512 = getJmEc512()

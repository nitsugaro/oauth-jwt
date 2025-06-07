package main

import (
	"encoding/json"
	"fmt"
	"time"

	oauthjwt "github.com/nitsugaro/oauth-jwt"
)

func main() {
	secret32, _ := oauthjwt.GenerateSecretKey(oauthjwt.SECRET_64)
	rsa2048, _ := oauthjwt.GenerateRsaKey(oauthjwt.RSA_2048)
	jm := &oauthjwt.JwtManager{
		FolderPath:        "./keys",
		KeyExpTimeMinutes: int64(90 * 24 * 60),
	}

	jm2 := &oauthjwt.JwtManager{
		FolderPath:        "./hola/keys2",
		KeyExpTimeMinutes: int64(90 * 24 * 60),
	}

	jm2.InitKeys()

	jm.ResetStorage()
	jm.InitKeys(secret32, rsa2048)

	jwtBuilder := jm.NewBuilder()

	jwtBuilder.SetSub("1233")
	jwtBuilder.SetAud("1234")
	jwtBuilder.SetIat(time.Now())

	fmt.Println(jm.SignHmac(jwtBuilder, oauthjwt.HS256_ALG))
	fmt.Println(jm.SignHmac(jwtBuilder, oauthjwt.HS384_ALG))
	fmt.Println(jm.SignHmac(jwtBuilder, oauthjwt.HS512_ALG))
	fmt.Println(jm.SignRsa(jwtBuilder, oauthjwt.RS512_ALG))
	fmt.Println(jm.SignRsa(jwtBuilder, oauthjwt.RS512_ALG))

	jwks := jm.GetPublicJWKs()

	bkp, _ := jm.GetKeysBkp()
	jm2.RestoreKeysBkp(bkp)
	bkpJSON, _ := json.MarshalIndent(bkp, "", "  ")

	println(string(bkpJSON))

	data, _ := json.MarshalIndent(map[string]interface{}{"keys": jwks}, "", "  ")
	println(string(data))
}

# Library to Sign JWT for OAuth2.0 and OIDC frameworks

Use this dependency for a simple adoption of JWT.

```bash
go get github.com/nitsugaro/oauth-jwt@latest
```

# Supported Algorithms

```json
HS256 HS384 HS512
RS256 RS384 RS512
RS256 ES384 ES512
```

# Usage Examples

### Generate Keys

```go
//for HMAC
oauthjwt.GenerateSecretKey(oauthjwt.SECRET_32)
oauthjwt.GenerateSecretKey(oauthjwt.SECRET_64)

//for RSA
oauthjwt..GenerateRsaKey(oauthjwt.RSA_2048)
oauthjwt..GenerateRsaKey(oauthjwt.RSA_3072)
oauthjwt..GenerateRsaKey(oauthjwt.RSA_4096)

//for EC
oauthjwt.GenerateEcKey(oauthjwt.ES256_ALG)
oauthjwt.GenerateEcKey(oauthjwt.ES384_ALG)
oauthjwt.GenerateEcKey(oauthjwt.ES512_ALG)
```

### Create JwtManager and Init Keys

```go
jm := &oauthjwt.JwtManager{
	FolderPath:        "./keys",
	Iss:               "TEST",
	KeyExpTimeMinutes: int64(90 * 24 * 60), //3 months
}

jm.InitKeys(secret32, rsa2048, ...)
```

### Sign and Verify JWTs

```go
jwtBuilder := jm.NewBuilder()

jwtBuilder.SetSub("1233")
jwtBuilder.SetIat(time.Now())
jwtBuilder.SetClaim("my-custom-claim", "my-custom-val")
jwtBuilder.SetHeader("my-custom-header", "my-custom-val")

/* SIGN */

//1.

jwtStr, err := jm.SignHmac(jwtBuilder, oauthjwt.HS256_ALG)

jm.SignHmac(jwtBuilder, oauthjwt.HS384_ALG)
jm.SignHmac(jwtBuilder, oauthjwt.HS512_ALG)

jm.SignRsa(jwtBuilder, oauthjwt.RS256_ALG)
jm.SignRsa(jwtBuilder, oauthjwt.RS384_ALG)
jm.SignRsa(jwtBuilder, oauthjwt.RS512_ALG)

jm.SignEc(jwtBuilder, oauthjwt.ES256_ALG)
jm.SignEc(jwtBuilder, oauthjwt.ES384_ALG)
jm.SignEc(jwtBuilder, oauthjwt.ES512_ALG)

//2.

jwtBuilder := jm.NewBuilder()
jwtBuilder.SetAlg(oauthjwt.HS256)
jwtStr, err := jm.Sign(jwtBuilder)

//3.

jwt, err := oauthjwt.ParseJwt(jwtStr)
jwtBuilder := jm.NewBuilderFromJwt(jwt)
jwtBuilder.SetClaim("new-claim", "new-claim-value")
jwtStr, err := jm.Sign(jwtBuilder)

jwks := jm.GetPublicJWKs()

/* VERIFY */

jwt, err := oauthjwt.ParseJwt(jwtStr)
if err == nil && jm.Verify(jwt) {
    //jwt is valid!!!
}
```

### Backup and Restore

```go
bkp, err := jm.GetKeysBkp()

if err == nil {
    jm2.RestoreKeysBkp(bkp)
}
```
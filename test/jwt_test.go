package main

import (
	"strings"
	"testing"

	oauthjwt "github.com/nitsugaro/oauth-jwt"
)

func testJwt(jwt string, jm *oauthjwt.JwtManager, t *testing.T) {
	if jwt == "" {
		t.Errorf("sign jwt expecred not get error and got an empty string")
	}

	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != 3 {
		t.Errorf("signed jwt must have 3 parts and got %v", len(jwtParts))
	}

	parsedJwt, err := oauthjwt.ParseJwt(jwt)
	if err != nil {
		t.Errorf("parse jwt got an error %v", err.Error())
	}

	if parsedJwt.GetSub() != "1234" {
		t.Errorf("expected sub claim '1234' and got %v", parsedJwt.GetSub())
	}

	if !jm.Verify(parsedJwt) {
		t.Errorf("expected verify jwt equal to 'true' but got 'false'")
	}

	jwtBuilder := jm.NewBuilderFromJwt(parsedJwt)
	jwtBuilder.SetClaim("new-claim", "new-claim-value")
	newJwt, err := jm.Sign(jwtBuilder)
	if err != nil {
		t.Errorf("sign jwt from jwtBuilder error: %v", err.Error())
	}

	newParsedJwt, err := oauthjwt.ParseJwt(newJwt)
	if err != nil {
		t.Errorf("parse new jwt got an error %v", err.Error())
	}

	if newParsedJwt.GetClaim("new-claim").(string) != "new-claim-value" {
		t.Errorf("new jwt claim 'new-claim' must be equal to 'new-claim-value' and got %s", newParsedJwt.GetClaim("new-claim"))
	}
}

func TestJwtHmac(t *testing.T) {
	jwtBuilder := jmHmac32.NewBuilder()
	sub := "1234"
	jwtBuilder.SetSub(sub)

	jwt32, err := jmHmac32.SignHmac(jwtBuilder, oauthjwt.HS256_ALG, nil)
	if err != nil {
		t.Errorf("sign jwt expecred not get error and got %s", err.Error())
	}
	testJwt(jwt32, jmHmac32, t)

	jwt64, err := jmHmac64.SignHmac(jwtBuilder, oauthjwt.HS512_ALG, nil)
	if err != nil {
		t.Errorf("sign jwt expecred not get error and got %s", err.Error())
	}
	testJwt(jwt64, jmHmac64, t)

	newBuilder := jmHmac32.NewBuilder()
	newBuilder.SetAlg(oauthjwt.HS256)
	jwtFromSign, err := jmHmac32.Sign(newBuilder)
	if err != nil || jwtFromSign == "" {
		t.Errorf("sign jwt from newBuilder error: %v", err.Error())
	}
}

func TestJwtRsa(t *testing.T) {
	jwtBuilder := jmRsa2048.NewBuilder()
	sub := "1234"
	jwtBuilder.SetSub(sub)

	/* RSA 2048 */
	jwt1, err := jmRsa2048.SignRsa(jwtBuilder, oauthjwt.RS256_ALG, nil)
	if err != nil {
		t.Errorf("sign jwt expecred not get error and got %s", err.Error())
	}
	testJwt(jwt1, jmRsa2048, t)

	jwt2, err := jmRsa2048.SignRsa(jwtBuilder, oauthjwt.RS384_ALG, nil)
	if err != nil {
		t.Errorf("sign jwt expecred not get error and got %s", err.Error())
	}
	testJwt(jwt2, jmRsa2048, t)

	jwt3, err := jmRsa2048.SignRsa(jwtBuilder, oauthjwt.RS512_ALG, nil)
	if err != nil {
		t.Errorf("sign jwt expecred not get error and got %s", err.Error())
	}
	testJwt(jwt3, jmRsa2048, t)

	/* RSA 3072 */
	jwt4, err := jmRsa3072.SignRsa(jwtBuilder, oauthjwt.RS256_ALG, nil)
	if err != nil {
		t.Errorf("sign jwt expecred not get error and got %s", err.Error())
	}
	testJwt(jwt4, jmRsa3072, t)

	jwt5, err := jmRsa3072.SignRsa(jwtBuilder, oauthjwt.RS384_ALG, nil)
	if err != nil {
		t.Errorf("sign jwt expecred not get error and got %s", err.Error())
	}
	testJwt(jwt5, jmRsa3072, t)

	jwt6, err := jmRsa3072.SignRsa(jwtBuilder, oauthjwt.RS512_ALG, nil)
	if err != nil {
		t.Errorf("sign jwt expecred not get error and got %s", err.Error())
	}
	testJwt(jwt6, jmRsa3072, t)

	/* RSA 4096 */
	jwt7, err := jmRsa4096.SignRsa(jwtBuilder, oauthjwt.RS256_ALG, nil)
	if err != nil {
		t.Errorf("sign jwt expecred not get error and got %s", err.Error())
	}
	testJwt(jwt7, jmRsa4096, t)

	jwt8, err := jmRsa4096.SignRsa(jwtBuilder, oauthjwt.RS384_ALG, nil)
	if err != nil {
		t.Errorf("sign jwt expecred not get error and got %s", err.Error())
	}
	testJwt(jwt8, jmRsa4096, t)

	jwt9, err := jmRsa4096.SignRsa(jwtBuilder, oauthjwt.RS512_ALG, nil)
	if err != nil {
		t.Errorf("sign jwt expecred not get error and got %s", err.Error())
	}
	testJwt(jwt9, jmRsa4096, t)
}

func TestJwtEc(t *testing.T) {
	jwtBuilder := jmEc256.NewBuilder()
	sub := "1234"
	jwtBuilder.SetSub(sub)

	/* EC 256 */
	jwt1, err := jmEc256.SignEc(jwtBuilder, oauthjwt.ES256_ALG, nil)
	if err != nil {
		t.Errorf("sign jwt expecred not get error and got %s", err.Error())
	}
	testJwt(jwt1, jmEc256, t)

	/* EC 384 */
	jwt2, err := jmEc384.SignEc(jwtBuilder, oauthjwt.ES384_ALG, nil)
	if err != nil {
		t.Errorf("sign jwt expecred not get error and got %s", err.Error())
	}
	testJwt(jwt2, jmEc384, t)

	/* EC 512 */
	jwt3, err := jmEc512.SignEc(jwtBuilder, oauthjwt.ES512_ALG, nil)
	if err != nil {
		t.Errorf("sign jwt expecred not get error and got %s", err.Error())
	}
	testJwt(jwt3, jmEc512, t)
}

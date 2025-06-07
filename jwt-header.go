package oauthjwt

type jwtHeader struct {
	*jwtPart
}

func (headers *jwtHeader) GetType() string {
	return headers.GetStr("type")
}

func (headers *jwtHeader) SetType(typ string) {
	headers.setField("type", typ)
}

func (headers *jwtHeader) GetAlg() ALG {
	return ALG(headers.GetStr("alg"))
}

func (headers *jwtHeader) SetAlg(alg ALG) {
	headers.setField("alg", alg)
}

func (headers *jwtHeader) GetKid() string {
	return headers.GetStr("kid")
}

func (headers *jwtHeader) SetKid(kid string) {
	headers.setField("kid", kid)
}

func (headers *jwtHeader) GetJwk() map[string]interface{} {
	return headers.getField("jwk").(map[string]interface{})
}

func (headers *jwtHeader) SetJwk(jwk map[string]interface{}) {
	headers.setField("jwk", jwk)
}

func (headers *jwtHeader) GetHeader(key string) interface{} {
	return headers.getField(key)
}

func (headers *jwtHeader) SetHeader(key string, val interface{}) *jwtHeader {
	headers.setField(key, val)

	return headers
}

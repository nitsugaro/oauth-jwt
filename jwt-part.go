package oauthjwt

import (
	"encoding/base64"
	"encoding/json"
)

type jwtPart map[string]interface{}

func GetPartFromBase64Url(base64Url string) (*jwtPart, error) {
	base64Bytes, err := base64.RawURLEncoding.DecodeString(base64Url)
	if err != nil {
		return nil, err
	}

	var jwtPart = jwtPart{}
	err = json.Unmarshal(base64Bytes, &jwtPart)
	if err != nil {
		return nil, err
	}

	return &jwtPart, nil
}

func (jwtPart *jwtPart) EncodeBase64Url() (string, error) {
	jsonBytes, err := json.Marshal(*jwtPart)
	if err != nil {
		return "", err
	}

	base64URL := base64.RawURLEncoding.EncodeToString(jsonBytes)
	return base64URL, nil
}

func (jwtPart *jwtPart) setField(name string, val interface{}) {
	(*jwtPart)[name] = val
}

func (jwtPart *jwtPart) getField(name string) interface{} {
	return (*jwtPart)[name]
}

func (jwtPart *jwtPart) GetStr(name string) string {
	return ToStr(jwtPart.getField(name))
}

func (jwtPart *jwtPart) GetInt(name string) int {
	return ToInt(jwtPart.getField(name))
}

func (jwtPart *jwtPart) GetInt64(name string) int64 {
	return ToInt64(jwtPart.getField(name))
}

func (jwtPart *jwtPart) GetFloat32(name string) float32 {
	return ToFloat32(jwtPart.getField(name))
}

func (jwtPart *jwtPart) GetFloat64(name string) float64 {
	return ToFloat64(jwtPart.getField(name))
}

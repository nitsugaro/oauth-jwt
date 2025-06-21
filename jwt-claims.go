package oauthjwt

import (
	"time"
)

type IJwtClaims interface {
	GetSub() string
	SetSub(string)

	GetIss() string
	SetIss(string)

	GetAud() string
	SetAud(string)

	GetJti() string
	SetJti(string)

	GetScope() string
	SetScope(string)

	GetIat() time.Time
	SetIat(time.Time)

	GetExp() time.Time
	SetExp(time.Time)

	GetClaim(string) interface{}
	SetClaim(string, interface{}) *jwtClaims
}

type jwtClaims struct {
	*jwtPart
}

func (c *jwtClaims) GetSub() string {
	return c.GetStr("sub")
}

func (c *jwtClaims) SetSub(sub string) {
	c.setField("sub", sub)
}

func (c *jwtClaims) GetIss() string {
	return c.GetStr("iss")
}

func (c *jwtClaims) SetIss(iss string) {
	c.setField("iss", iss)
}

func (c *jwtClaims) GetAud() string {
	return c.GetStr("aud")
}

func (c *jwtClaims) SetAud(aud string) {
	c.setField("aud", aud)
}

func (c *jwtClaims) GetJti() string {
	return c.GetStr("jti")
}

func (c *jwtClaims) SetJti(jti string) {
	c.setField("jti", jti)
}

func (c *jwtClaims) GetScope() string {
	return c.GetStr("scope")
}

func (c *jwtClaims) SetScope(scope string) {
	c.setField("scope", scope)
}

func (c *jwtClaims) GetIat() time.Time {
	return time.Unix(c.GetInt64("iat"), 0)
}

func (c *jwtClaims) SetIat(iat time.Time) {
	c.setField("iat", iat.Unix())
}

func (c *jwtClaims) GetExp() time.Time {
	return time.Unix(c.GetInt64("exp"), 0)
}

func (c *jwtClaims) SetExp(exp time.Time) {
	c.setField("exp", exp.Unix())
}

func (c *jwtClaims) SetClaim(key string, val interface{}) *jwtClaims {
	c.setField(key, val)

	return c
}

func (c *jwtClaims) GetClaim(key string) interface{} {
	return c.getField(key)
}

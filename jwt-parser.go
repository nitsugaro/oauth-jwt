package oauthjwt

import (
	"strings"
)

func ParseJwt(jwt string) (IJwt, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidFormatJwt
	}

	header := parts[0]
	payload := parts[1]
	signature := parts[2]
	parsedJwt := &Jwt{
		headerBase64Url: header,
		claimsBase64Url: payload,
		signature:       signature,
	}

	if len(signature) == 0 {
		return nil, ErrInvalidSginatureJwt
	}

	headersDecoded, err := GetPartFromBase64Url(header)
	if err != nil {
		return nil, ErrInvalidFormatJwt
	}

	claimsDecoded, err := GetPartFromBase64Url(payload)
	if err != nil {
		return nil, ErrInvalidFormatJwt
	}

	parsedJwt.jwtHeader = &jwtHeader{headersDecoded}
	parsedJwt.jwtClaims = &jwtClaims{claimsDecoded}

	return parsedJwt, nil
}

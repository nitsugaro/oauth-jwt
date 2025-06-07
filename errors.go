package oauthjwt

import "errors"

/* KEYS ERRORS */
var ErrDecodePem = errors.New("there was an error trying to decode key pem")
var ErrInvalidKeyTypeFile = errors.New("invalid key type from file")

/* HASH ERRORS */
var ErrInvalidShaAlg = errors.New("invalid sha alg error")

/* SECRET ERRORS */
var ErrSecretKeyLength = errors.New("secret key just accept 32 or 64 bits")

/* EC ERRORS */
var ErrEcKeyCrv = errors.New("ec key crv is not valid")

/* RSA ERRORS */
var ErrRsaKeyBits = errors.New("rsa key bits is not valid")

/* JWT ERRORS */
var ErrInvalidFormatJwt = errors.New("jwt malformed")
var ErrInvalidAlgHeaderJwt = errors.New("jwt headers doesn't have supported 'alg' header")
var ErrInvalidSginatureJwt = errors.New("jwt invalid signature")
var ErrRequiredHeader = errors.New("jwt headers doesn't have required fields")
var ErrRequiredPayload = errors.New("jwt payload doesn't have required fields")

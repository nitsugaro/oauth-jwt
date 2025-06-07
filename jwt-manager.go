package oauthjwt

import (
	"math/rand"
	"os"
	"time"
)

/*
Found a random key by kty.
If it's expired generated a new one.
If doesn't have a prev one returns nil pointer
*/
func (jm *JwtManager) randomKeyByKty(kty string) *Key {
	keysFoundValid := []*Key{}
	keysFoundExpired := []*Key{}
	for _, key := range jm.keys {
		if key.kty == kty {
			if jm.IsExpiredKey(key) {
				keysFoundExpired = append(keysFoundExpired, key)
			} else {
				keysFoundValid = append(keysFoundValid, key)
			}
		}
	}

	if len(keysFoundValid) != 0 {
		return keysFoundValid[rand.Intn(len(keysFoundValid))]
	}

	if len(keysFoundExpired) == 0 {
		return nil
	}

	keyFoundExpired := keysFoundExpired[rand.Intn(len(keysFoundExpired))]
	keyFoundExpired, _ = jm.RegenerateKey(keyFoundExpired)

	return keyFoundExpired
}

type JwtManager struct {
	FolderPath        string
	Iss               string
	KeyExpTimeMinutes int64
	keys              []*Key
}

func (jm *JwtManager) GetIss() string {
	if jm.Iss != "" {
		return jm.Iss
	}

	return "NITSU-JWT"
}

func (jm *JwtManager) GetKey(kid string) *Key {
	for _, key := range jm.keys {
		if key.kid == kid {
			return key
		}
	}

	return nil
}

func (jm *JwtManager) GetKeyForSignSecret() *Key {
	return jm.randomKeyByKty(SECRET_KTY)
}

func (jm *JwtManager) GetKeyForSignRsa() *Key {
	return jm.randomKeyByKty(RSA_KTY)
}

func (jm *JwtManager) GetKeyForSignEc(alg ES_ALG) *Key {
	return jm.randomKeyByKty(EC_KTY + "-" + string(alg))
}

/* Save key to current state and file */
func (jm *JwtManager) SetKey(keysToSave ...*Key) {
	jm.keys = append(jm.keys, keysToSave...)
	jm.saveKeyToFile(keysToSave...)
}

/* Empty file keys */
func (jm *JwtManager) ResetStorage() {
	os.RemoveAll(jm.GetFolderPath())
	os.MkdirAll(jm.GetFolderPath(), 0755)
}

func (jm *JwtManager) DeleteKey(kid string) bool {
	key := jm.GetKey(kid)
	if key == nil {
		return true
	}

	jm.keys = Filter(jm.keys, func(k *Key) bool {
		return k.kid != kid
	})

	filepath := getFileKeyName(key)

	return os.Remove(filepath) == nil
}

func (jm *JwtManager) GetFolderPath() string {
	return jm.FolderPath
}

func (jm *JwtManager) GetKeyExpTimeMinutes() int64 {
	return jm.KeyExpTimeMinutes
}

func (jm *JwtManager) IsExternalJwt(jwt *Jwt) bool {
	return jwt.GetIss() != jm.GetIss()
}

func (jm *JwtManager) IsExpiredKey(k *Key) bool {
	return time.Now().Unix()-k.iat >= jm.GetKeyExpTimeMinutes()*60
}

func (jm *JwtManager) InitKeys(defaultKeys ...*Key) bool {
	jm.keys = []*Key{}
	keysSaved, err := jm.LoadKeysFromFolder()

	if err == nil && len(keysSaved) != 0 {
		jm.keys = keysSaved
	} else {
		jm.ResetStorage()
		jm.SetKey(defaultKeys...)
	}

	return true
}

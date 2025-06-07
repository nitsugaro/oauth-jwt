package oauthjwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func getFileKeyName(k *Key) string {
	return k.kid + ":" + k.kty + ":" + fmt.Sprintf("%d", k.iat) + ":" + k.param + ".pem"
}

func (jm *JwtManager) saveKeyToFile(keysToSave ...*Key) error {
	for _, k := range keysToSave {
		var privBytes []byte
		var typ string
		switch k.GetKty() {
		case RSA_KTY:
			privBytes = x509.MarshalPKCS1PrivateKey(k.value.(*rsa.PrivateKey))
			typ = "RSA PRIVATE KEY"
		case SECRET_KTY:
			bytes, _ := base64.StdEncoding.DecodeString(k.value.(string))
			privBytes = bytes
			typ = "SECRET KEY"
		case EC_KTY:
			bytes, _ := x509.MarshalECPrivateKey(k.value.(*ecdsa.PrivateKey))
			privBytes = bytes
			typ = "EC PRIVATE KEY"
		default:
			return ErrInvalidKeyTypeFile
		}

		err := os.WriteFile(jm.GetFolderPath()+"/"+getFileKeyName(k), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: privBytes}), 0600)
		if err != nil {
			return err
		}
	}

	return nil
}

func (jm *JwtManager) LoadKeysFromFolder() ([]*Key, error) {
	var keys []*Key

	err := filepath.WalkDir(jm.GetFolderPath(), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".pem") {
			return nil
		}

		filename := strings.Split(strings.TrimSuffix(d.Name(), ".pem"), ":")
		kid := filename[0]
		kty := filename[1]
		exp, err := strconv.ParseInt(filename[2], 10, 64)
		if err != nil {
			return err
		}
		param := filename[3]

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		block, _ := pem.Decode(data)
		if block == nil {
			return ErrDecodePem
		}

		var privKey interface{}
		switch block.Type {
		case "RSA PRIVATE KEY":
			priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return err
			}
			privKey = priv
		case "EC PRIVATE KEY":
			priv, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return err
			}
			privKey = priv
		case "SECRET KEY":
			privKey = base64.StdEncoding.EncodeToString(block.Bytes)
		default:
			return ErrInvalidKeyTypeFile
		}

		keys = append(keys, &Key{
			kid:   kid,
			kty:   kty,
			param: param,
			iat:   exp,
			value: privKey,
		})
		return nil
	})

	return keys, err
}

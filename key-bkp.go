package oauthjwt

import (
	"encoding/base64"
	"os"
	"path/filepath"
)

type KeyBkp struct {
	FileName        string `json:"fileName"`
	FileValueBase64 string `json:"fileValueBase64"`
}

func (jm *JwtManager) GetKeysBkp() ([]KeyBkp, error) {
	keysBkp := make([]KeyBkp, len(jm.keys))
	for i, key := range jm.keys {
		fileName := getFileKeyName(key)
		fullPath := filepath.Join(jm.GetFolderPath(), fileName)

		data, err := os.ReadFile(fullPath)
		var encoded string
		if err != nil {
			return nil, err
		}

		encoded = base64.StdEncoding.EncodeToString(data)
		keysBkp[i] = KeyBkp{
			FileName:        fileName,
			FileValueBase64: encoded,
		}
	}

	return keysBkp, nil
}

func (jm *JwtManager) RestoreKeysBkp(keysBkp []KeyBkp) error {
	jm.ResetStorage()

	for _, bkp := range keysBkp {
		data, err := base64.StdEncoding.DecodeString(bkp.FileValueBase64)
		if err != nil {
			return err
		}

		fullPath := filepath.Join(jm.GetFolderPath(), bkp.FileName)
		err = os.WriteFile(fullPath, data, 0600)
		if err != nil {
			return err
		}
	}

	keysSaved, err := jm.LoadKeysFromFolder()
	if err != nil {
		return err
	}

	jm.keys = keysSaved

	return nil
}

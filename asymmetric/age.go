package asymmetric

import (
	"bytes"
	"encoding/base64"
	"filippo.io/age"
	"io"
)

func AgeEncrypt(publicKey string, data string) (string, error) {
	recipient, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		return "", err
	}

	encout := bytes.Buffer{}

	w, err := age.Encrypt(&encout, recipient)
	if err != nil {
		return "", err
	}
	if _, err := io.WriteString(w, data); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}

	encrypted := base64.StdEncoding.EncodeToString(encout.Bytes())
	return encrypted, nil
}

func AgeDecrypt(privateKey string, data string) (string, error) {
	decoded, dErr := base64.StdEncoding.DecodeString(data)
	if dErr != nil {
		return "", dErr
	}
	rdr := bytes.NewBuffer(decoded)

	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		return "", err
	}

	r, err := age.Decrypt(rdr, identity)
	if err != nil {
		return "", err
	}
	plainout := &bytes.Buffer{}
	if _, err := io.Copy(plainout, r); err != nil {
		return "", err
	}

	return plainout.String(), nil
}

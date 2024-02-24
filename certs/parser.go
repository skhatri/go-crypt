package certs

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"
)

func decodeData(data string) string {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return data
	}
	return decodeData(string(decoded))
}

func ExtractCertificateAttributes(data string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	decoded := decodeData(data)
	block, _ := pem.Decode([]byte(decoded))
	certBytes := make([]byte, 0)
	if block != nil {
		certBytes = block.Bytes
	} else {
		certBytes = []byte(decoded)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	result["common-name"] = cert.Subject.CommonName
	result["san"] = cert.DNSNames
	result["issuer"] = cert.Issuer.CommonName
	result["created"] = cert.NotBefore.Format(time.RFC3339)
	result["expiry"] = cert.NotAfter.Format(time.RFC3339)
	return result, nil
}

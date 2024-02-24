package certs

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"
)

func ExtractCertificateAttributes(data string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	decoded, derr := base64.StdEncoding.DecodeString(data)
	if derr != nil {
		decoded = []byte(data)
	}

	block, _ := pem.Decode(decoded)
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PEM parse error: %w", err)
		}
		result["CommonName"] = cert.Subject.CommonName
		result["SAN"] = fmt.Sprint(cert.DNSNames)
		result["Issuer"] = cert.Issuer.CommonName
		result["ExpiryDate"] = cert.NotAfter.Format(time.RFC3339)
		result["CreatedDate"] = cert.NotBefore.Format(time.RFC3339)
		return result, nil
	}

	cert, err := x509.ParseCertificate(decoded)
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

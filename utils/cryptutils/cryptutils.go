// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2021 Renesas Inc.
// Copyright 2021 EPAM Systems Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cryptutils

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const (
	// PEMExt PEM format extension
	PEMExt = "pem"
)

// PEM block types
const (
	PEMBlockRSAPrivateKey      = "RSA PRIVATE KEY"
	PEMBlockECPrivateKey       = "EC PRIVATE KEY"
	PEMBlockCertificate        = "CERTIFICATE"
	PEMBlockCertificateRequest = "CERTIFICATE REQUEST"
)

// Crypto algorithm
const (
	AlgRSA = "rsa"
	AlgECC = "ecc"
)

// URL schemes
const (
	SchemeFile   = "file"
	SchemeTPM    = "tpm"
	SchemePKCS11 = "pkcs11"
)

/*******************************************************************************
 * Public
 ******************************************************************************/

// GetCaCertPool returns CA cert pool
func GetCaCertPool(rootCaFilePath string) (caCertPool *x509.CertPool, err error) {
	pemCA, err := ioutil.ReadFile(rootCaFilePath)
	if err != nil {
		return nil, err
	}

	caCertPool = x509.NewCertPool()

	if !caCertPool.AppendCertsFromPEM(pemCA) {
		return nil, fmt.Errorf("failed to add CA's certificate")
	}

	return caCertPool, nil
}

// GetClientMutualTLSConfig returns client mutual TLS configuration
func GetClientMutualTLSConfig(CACert, certStorageDir string) (config *tls.Config, err error) {
	certPool, err := GetCaCertPool(CACert)
	if err != nil {
		return nil, err
	}

	clientCert, err := getKeyPairFromDir(certStorageDir)
	if err != nil {
		return nil, err
	}

	config = &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
	}

	return config, nil
}

// GetClientTLSConfig returns client TLS configuration
func GetClientTLSConfig(certStorageDir string) (config *tls.Config, err error) {
	clientCert, err := getKeyPairFromDir(certStorageDir)
	if err != nil {
		return nil, err
	}

	config = &tls.Config{
		Certificates: []tls.Certificate{clientCert},
	}

	return config, nil
}

// GetServerMutualTLSConfig returns server mutual TLS configuration
func GetServerMutualTLSConfig(CACert, certStorageDir string) (config *tls.Config, err error) {
	certPool, err := GetCaCertPool(CACert)
	if err != nil {
		return nil, err
	}

	serverCert, err := getKeyPairFromDir(certStorageDir)
	if err != nil {
		return nil, err
	}

	config = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	return config, nil
}

// GetServerTLSConfig returns server TLS configuration
func GetServerTLSConfig(certStorageDir string) (config *tls.Config, err error) {
	serverCert, err := getKeyPairFromDir(certStorageDir)
	if err != nil {
		return nil, err
	}

	config = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
	}

	return config, nil
}

// PEMToX509Key parses PEM data to x509 key structures
func PEMToX509Key(data []byte) (key crypto.PrivateKey, err error) {
	block, _ := pem.Decode(data)
	if err != nil {
		return nil, err
	}

	if block != nil {
		data = block.Bytes
	}

	switch {
	case block == nil:
		if key, err = parseKey(data); err != nil {
			return nil, err
		}

	case block.Type == PEMBlockRSAPrivateKey:
		if key, err = x509.ParsePKCS1PrivateKey(data); err != nil {
			return nil, err
		}

	case block.Type == PEMBlockECPrivateKey:
		if key, err = x509.ParseECPrivateKey(data); err != nil {
			return nil, err
		}

	default:
		if key, err = parseKey(data); err != nil {
			return nil, err
		}
	}

	return key, nil
}

// LoadKey loads key from file
func LoadKey(fileName string) (key crypto.PrivateKey, err error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	if key, err = PEMToX509Key(data); err != nil {
		return nil, err
	}

	return key, nil
}

// SaveKey saves key to file
func SaveKey(fileName string, key crypto.PrivateKey) (err error) {
	file, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	switch privateKey := key.(type) {
	case *rsa.PrivateKey:
		if err = pem.Encode(file, &pem.Block{Type: PEMBlockRSAPrivateKey, Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
			return err
		}

	case *ecdsa.PrivateKey:
		data, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return err
		}

		if err = pem.Encode(file, &pem.Block{Type: PEMBlockECPrivateKey, Bytes: data}); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unsupported key type: %v", reflect.TypeOf(privateKey))
	}

	return nil
}

// PEMToX509Cert parses PEM data to x509 certificate structures
func PEMToX509Cert(data []byte) (certs []*x509.Certificate, err error) {
	var block *pem.Block

	for {
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == PEMBlockCertificate {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}

			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("wrong certificate PEM format")
	}

	return certs, nil
}

// LoadCertificate loads certificate from file
func LoadCertificate(fileName string) (certs []*x509.Certificate, err error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	if certs, err = PEMToX509Cert(data); err != nil {
		return nil, err
	}

	return certs, nil
}

// SaveCertificate saves certificate to file
func SaveCertificate(fileName string, certs []*x509.Certificate) (err error) {
	file, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, cert := range certs {
		if err = pem.Encode(file, &pem.Block{Type: PEMBlockCertificate, Bytes: cert.Raw}); err != nil {
			return err
		}
	}

	return nil
}

// CheckCertificate checks if certificate matches key
func CheckCertificate(cert *x509.Certificate, key crypto.PrivateKey) (err error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("private key does not implement public key interface")
	}

	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}

	if !bytes.Equal(pub, cert.RawSubjectPublicKeyInfo) {
		return errors.New("certificate verification error")
	}

	return nil
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func getKeyPairFromDir(dir string) (cert tls.Certificate, err error) {
	content, err := ioutil.ReadDir(dir)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Collect keys

	keyMap := make(map[string]crypto.PrivateKey)

	for _, item := range content {
		absItemPath := path.Join(dir, item.Name())

		if item.IsDir() {
			continue
		}

		key, err := LoadKey(absItemPath)
		if err != nil {
			continue
		}

		keyMap[absItemPath] = key
	}

	for _, item := range content {
		absItemPath := path.Join(dir, item.Name())

		if item.IsDir() {
			continue
		}

		certs, err := LoadCertificate(absItemPath)
		if err != nil {
			continue
		}

		if len(certs) < 1 {
			continue
		}

		for keyFilePath, key := range keyMap {
			if CheckCertificate(certs[0], key) == nil {
				return tls.LoadX509KeyPair(absItemPath, keyFilePath)
			}
		}
	}

	return tls.Certificate{}, errors.New("no appropriate key & certificate pair found")
}

func parseKey(data []byte) (key crypto.PrivateKey, err error) {
	if key, err = x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, nil
	}

	if key, err = x509.ParseECPrivateKey(data); err == nil {
		return key, nil
	}

	if key, err = x509.ParsePKCS8PrivateKey(data); err == nil {
		return key, nil
	}

	return nil, errors.New("invalid key format")
}

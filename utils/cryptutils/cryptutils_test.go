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

package cryptutils_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"testing"

	"gitpct.epam.com/epmd-aepr/aos_common/aoserrors"
	"gitpct.epam.com/epmd-aepr/aos_common/utils/cryptutils"
	"gitpct.epam.com/epmd-aepr/aos_common/utils/testtools"
)

/*******************************************************************************
 * Vars
 ******************************************************************************/

var tmpDir string

/*******************************************************************************
 * Main
 ******************************************************************************/

func TestMain(m *testing.M) {
	var err error

	tmpDir, err = ioutil.TempDir("", "aos_")
	if err != nil {
		log.Fatalf("Error create temporary dir: %s", err)
	}

	ret := m.Run()

	if err := os.RemoveAll(tmpDir); err != nil {
		log.Fatalf("Error removing tmp dir: %s", err)
	}

	os.Exit(ret)
}

/*******************************************************************************
 * Tests
 ******************************************************************************/

func TestGetCertPool(t *testing.T) {
	fileName, err := savePEMFile(testtools.GetCACertificate())
	if err != nil {
		t.Fatalf("Can't save PRM file: %s", err)
	}

	if _, err = cryptutils.GetCaCertPool(fileName); err != nil {
		t.Errorf("Can't create CA cert pool: %s", err)
	}
}

func TestLoadKey(t *testing.T) {
	type privateKeyPEMTest struct {
		name string
		pem  []byte
		err  error
	}

	var testPEMKeys = []privateKeyPEMTest{
		{
			"RSA PRIVATE KEY (RSA 1024, success)",
			// openssl genrsa 1024
			[]byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCsK28HcO50LTeTvy00ZQR35NDp/9dArLt4A+6OwH3inUV9syUF
oY+JqucruFlmywE7gVAlCC+++mQ2CBDAfA45/10QRLgQtwESSxkXu/PlzxlrNMy+
GJVZneaWekEqdsst44o2hkj62G4LQQLsCNJeHaHuIfmmuJDA5dfSyyCd8wIDAQAB
AoGBAJ+u6RuNspwuFA4Ekni1+J76qoldsNdbXcTCYNAl2JwGIh2jugKvBeI5kI8M
PF8KieoW1a6DGUWYFrnGYUMlzEqZDfxxP/SLD3bl1MSBlm6ocNOb3LiLeDIr6jnb
JExgMemMBLfa0VRRjuroBNOuw1AAhzodtX1y2V3wwoji8JCBAkEA0no0N3qGc4Nz
WgukpqDZQ3kIp+B4wXD5emfYG3IBX3YrDBOdA6aoZq1iIw/3KKXv7DmadNe2mb+g
/EmHu6ZrtQJBANFoMZFmWglAj44l3f+Uetx9959ipleLFPxb4XS3rbArzBC/soMz
rXiLggD5YFdq5xFNIBroAZsMWpAh5UjIfAcCQHo+3/UZBN4yitzRxl/BLG8z7QMU
LQ6tPzkI90t5e7KmP3pUKe3k7go0ybrzmunQ9viMvFkAsN27nxTo4BztG8ECQDGN
Sk1xvtR5pn6oj0OvSvNqC3J30YzdqHWe+Fa6MCuD8aH0+rT5QY9I09aPLDEDZvI9
Id+8DsU1wyhgHPWAG3kCQBNhPwLP5V1nsgNaNpMwAu9zrRH2gHAhJPkeAG0LzyG1
W9yuEtRucDgho/TSGNY2klO3B+MicrbPiXiLZWxfiVg=
-----END RSA PRIVATE KEY-----`),
			nil,
		},

		{
			"PRIVATE KEY (RSA 1024, success)",
			// openssl genrsa 1024 | openssl pkcs8 -topk8 -nocrypt -outform pem
			[]byte(`-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAJvV2uczJ2bgcG5L
gAR9jh9NiIubQ7f2ouYOGEVmftwyoVHPqonaAIaXtAuQbRjExB9gCtF4qsnJtUlh
qiIIU+8lbOCyk8q/WFYFOmIyNaRWiNfnOpYQrkW/WdCbu5bOTyPFJQhmAFbBRC9m
9ms8+KmJa/Ka+wLLk/42zNWFOs3jAgMBAAECgYBa53dYoxh7BLXRQS2ecPd0/y+F
8L6iE7eW5+X0pgOew9Ii/TcITyk7Wkdm74sUhcO6YbYt12wZZhbghZ5PV/hNgaO8
ty7DeEVy3YCuCd7gYlPaUqAPk76HltIT5QI5syLA6KnGkZw2oUsCq6kNuitBCzd5
+B/N73qLvnEfZA1K8QJBAM8NoU7mTgD1PQpLpmJgkuK4EMbkfn2NsChZvq3fAKbd
cFBsZyOlPLq6tD7ZcruXXpT02PpuZjUhEyODThfG260CQQDArKQmOPC3hiAEsuYC
IP0/jlG8nLygcFeE9m+acC6RAHPik4mZOoQLezfasTfAJQtuOjxv74CdhFjm0WKJ
UYHPAkBp0Mhwfyi8OpjQaysEOeC3d2QzkVDHr6KobH0TdNVrcd3VbCElyWuI7qPx
PsXw8wIGVD+TdNpNKrMSQiel5R4dAkBKkwe925AgGIPQDcZE0Kv0q4sra6b+mjzl
s9SifAUqDnjMG7rIWgO9xeVqeelQL4ZrFZNK5/JqBU27mROAftG1AkAqmW56Jiqr
iHMlKtL3UphD/aujRhUMG2tVJb20/cSYN5Y9435BGQ1ZAeUPAOHFGLMFXlCGoTiN
X/PNGUlrN+wK
-----END PRIVATE KEY-----`),
			nil,
		},
		{
			"PRIVATE KEY (RSA 2048 (generated by python), success)",
			[]byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCoaouLdRhaTfxV
70TmRC2Gu5zG/f/2+HY16KRYUdUTD4VIiIu3z2afuURJaOhBL4ea8Txm4kC5nTh6
U1Ta11NRhjIMMrS/N8pB1IXCFPUEtJPbOKSdbDcHZ5kMMbqDA9myhaJvNvqpPg5t
bzgaBGhfT3J3wc4srWzNO/lJxZYcM7D7AyGhUbuQ2fsedDmQ706IeBzr0yFdGka+
RRTezKmjgSwXwsRTExDoQMqhcXI8scDQZ/Xse0YKEO4OTE+Tmf0puKnmLOr0ORrT
++7unk3XaRrT23gUPumayxsqH8M9ZOlsWnIOr8A27xAiT8KYLsHgcumQIY4zMj4E
wzSVZscLAgMBAAECggEAH1vvbeE4zp/Uy3+I+cNaIstOTvM+tRLgl/sglt1t6mWq
cK4ULf6tYjJSF8Uz8edSvbQLhjC80pMG0CgyFamgdv6g1QqgAzb1LzrOSSwzz1N8
cIZkiHd866ELq2ybCQgvggFGFKVNGTRX5WKfNKD7ejvF2ay5ojIMn056hZUH9WoR
PfKpNQt468MSYKGmG8BXETie03eTA34m1+RyLvmh4zCSLGUqOTrl18NsXRdkfPiZ
sdEn8j02rr4zfkRqFow1ORSxfG2OrcmqgDSqfrDYksGZziQniGuL5GfSsGHfC1c+
Gee2rFFIQ/HPjeUF461LbWhz170iGhiMt04ydtTMKQKBgQDWPY+Hw0O11ilyb1Ra
UbyDvEmJPKf1gqJlHDdWzNBF7ND617I5vigjXwbC7YQzcHotAaBFMK8qXLkbNSxG
L7QROe6o7Rtq85wNG9JIt9V2KfBF2/AgUzzeWXHm7N5Auk/yfDA6M7/d1ub37O72
iLNaA8n2pGPrQtSS28SBYdYp7wKBgQDJPmMb1cZnFddR9SEIBUR7FrQ1Z7/l/mah
Sovnvt+Gqt4mBwnAl8oIOkzYV/u6sFW6/JmgbM9h5JTty64Npk9Hu3h4O5xwIqzd
g3t4tEqcELJHtHl1J1bVEaZBg6s2FUZRT2k0TyiZB5sZ3zp+uB+6SuIcI7Y2pLQ1
aUD0bD5ApQKBgQCf2CR7tbuSMuyPnfLAxJUzcMso4qGqMsJ5T/kWARAv68XsMfye
ynrmESNZUp89ReFSLRFoLi+zGqVdYGndIABojeG8FdRMEuBOg4B8kvRoClhjtvpN
E+2pM/Egy3/zqU626+OLuUqg+JMxTYzpUgsG0Sbhp7uJLz6tJ91Qby+77wKBgEIM
JLDs/1mz1GBEqFuehvQy5mAktdmBHiPPeI1NmsTy7UfjxXKdHqSGpdPXRHnoB6r/
3lfFfmatg6dr0qsOKzTqtUYYomY3Ky7kSTC7U0VXQXvBIp+tkpUJXtxfn2B3qQVk
n62YUUWwNlpOZj9SpK8aho0ft1zFv5NMARJ3OBM1AoGAP7QGPolOUtndAGoQXWqP
SBUw9fqH6KMlFEDs8IjVTq49Gb3F6PUK/hkI47kFT5+86VK4wZIbZMhdfHNGzb8y
gfJB2R6A3jbBPTF7i8tb0iTNK+dikgH3hUAR3z6cs6bpgQRPXvTqeuM0acQuF4Z7
1IpqlVhnZ1jMRJcoQb/FeWs=
-----END PRIVATE KEY-----`),
			nil,
		},
	}

	for _, test := range testPEMKeys {
		fileName, err := savePEMFile(test.pem)
		if err != nil {
			t.Fatalf("Can't save PRM file: %s", err)
		}

		_, err = cryptutils.LoadKey(fileName)

		if err != nil && test.err == nil {
			t.Errorf("Got error: %s. Test: %s", err, test.name)
		}

		if err == nil && test.err != nil {
			t.Errorf("Should get error: %s. Test: %s", test.err, test.name)
		}

		if err != nil && test.err != nil {
			if err.Error() != test.err.Error() {
				t.Errorf("Expect error: %s. But got error: %s. Test %s", test.err, err, test.name)
			}
		}
	}
}

func TestSaveKey(t *testing.T) {
	type saveKeyTest struct {
		keyType   string
		createKey func() (key crypto.PrivateKey, err error)
	}

	testData := []saveKeyTest{
		{"rsa", func() (key crypto.PrivateKey, err error) { return rsa.GenerateKey(rand.Reader, 2048) }},
		{"ec", func() (key crypto.PrivateKey, err error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) }},
	}

	for i, test := range testData {
		key, err := test.createKey()
		if err != nil {
			t.Fatalf("Can't create key: %s", err)
		}

		fileName := path.Join(tmpDir, fmt.Sprintf("key%d.%s", i, cryptutils.PEMExt))

		if err = cryptutils.SaveKey(fileName, key); err != nil {
			t.Fatalf("Can't save key: %s", err)
		}

		out, err := exec.Command("openssl", test.keyType, "-check", "-in", fileName).CombinedOutput()
		if err != nil {
			t.Fatalf("Can't verify key: %s, %s", out, err)
		}
	}
}

func TestCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Can't generate key: %s", err)
	}

	csr, err := testtools.CreateCSR(key)
	if err != nil {
		t.Fatalf("Can't create CSR: %s", err)
	}

	initialCert, err := testtools.CreateCertificate(tmpDir, csr)
	if err != nil {
		t.Fatalf("Can't create certificate: %s", err)
	}

	fileName, err := savePEMFile(initialCert)
	if err != nil {
		t.Fatalf("Can't save PRM file: %s", err)
	}

	x509Cert, err := cryptutils.LoadCertificate(fileName)
	if err != nil {
		t.Fatalf("Can't load certificate: %s", err)
	}

	if err = cryptutils.CheckCertificate(x509Cert[0], key); err != nil {
		t.Errorf("Can't check certificate: %s", err)
	}

	certFile := path.Join(tmpDir, "cert.pem")

	if err = cryptutils.SaveCertificate(certFile, x509Cert); err != nil {
		t.Errorf("Can't save certificate: %s", err)
	}

	storedCert, err := ioutil.ReadFile(certFile)
	if err != nil {
		t.Fatalf("Can't read file: %s", err)
	}

	if !bytes.Equal(initialCert, storedCert) {
		t.Fatal("Cert data mismatch")
	}
}

func TestGetTLSConfig(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Can't generate key: %s", err)
	}

	csr, err := testtools.CreateCSR(key)
	if err != nil {
		t.Fatalf("Can't create CSR: %s", err)
	}

	cert, err := testtools.CreateCertificate(tmpDir, csr)
	if err != nil {
		t.Fatalf("Can't create certificate: %s", err)
	}

	tlsDir, err := ioutil.TempDir(tmpDir, "tlsconfig")
	if err != nil {
		t.Fatalf("Can't create TLS config dir: %s", err)
	}
	defer os.RemoveAll(tlsDir)

	x509Cert, err := cryptutils.PEMToX509Cert(cert)
	if err != nil {
		t.Fatalf("Can't parse certificate: %s", err)
	}

	if err = ioutil.WriteFile(path.Join(tlsDir, "root."+cryptutils.PEMExt), testtools.GetCACertificate(), 0600); err != nil {
		t.Fatalf("Can't save certificate: %s", err)
	}

	if err = cryptutils.SaveCertificate(path.Join(tlsDir, "cert."+cryptutils.PEMExt), x509Cert); err != nil {
		t.Fatalf("Can't save certificate: %s", err)
	}

	if err = cryptutils.SaveKey(path.Join(tlsDir, "key."+cryptutils.PEMExt), key); err != nil {
		t.Fatalf("Can't save certificate: %s", err)
	}

	if _, err = cryptutils.GetClientMutualTLSConfig(path.Join(tlsDir, "root."+cryptutils.PEMExt), tlsDir); err != nil {
		t.Errorf("Can't get client TLS config: %s", err)
	}

	if _, err = cryptutils.GetServerMutualTLSConfig(path.Join(tlsDir, "root."+cryptutils.PEMExt), tlsDir); err != nil {
		t.Errorf("Can't get server mutual TLS config: %s", err)
	}

	if _, err = cryptutils.GetClientTLSConfig(path.Join(tlsDir, "root."+cryptutils.PEMExt)); err != nil {
		t.Errorf("Can't get client TLS config: %s", err)
	}

	if _, err = cryptutils.GetServerTLSConfig(tlsDir); err != nil {
		t.Errorf("Can't get server TLS config: %s", err)
	}
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func savePEMFile(data []byte) (fileName string, err error) {
	file, err := ioutil.TempFile(tmpDir, "*."+cryptutils.PEMExt)
	if err != nil {
		return "", aoserrors.Wrap(err)
	}
	defer file.Close()

	if _, err = file.Write(data); err != nil {
		return "", aoserrors.Wrap(err)
	}

	return file.Name(), nil
}

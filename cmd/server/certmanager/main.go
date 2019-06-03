package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"

	"github.com/spf13/viper"

	"github.com/sirupsen/logrus"
)

var (
	configfile        = "config"
	CERTPATH          = "certs/"
	CAPATH            = CERTPATH + "CA/"
	SERVERPATH        = CERTPATH + "SERVER/"
	CLIENTPATH        = CERTPATH + "CLIENT/"
	serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

	rootTemplate = x509.Certificate{
		SerialNumber:          genSerialNumber(),
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	serverTemplate = x509.Certificate{
		SerialNumber:          genSerialNumber(),
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	clientTemplate = x509.Certificate{
		SerialNumber:          genSerialNumber(),
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
)

func init() {
	logrus.SetReportCaller(false)
}

type CertType int

const (
	CACert = iota
	ServerCert
	ClientCert
	InvalidCert
)

func (c CertType) String() string {
	return [...]string{"CA", "Server", "Client"}[c]
}

type CertPair struct {
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	CertType CertType
}

func CertLoad(path string, password ...string) CertPair {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		logrus.WithError(err).Error("Unable to read " + path)
		return CertPair{CertType: InvalidCert}
	}
	certcount := 0
	keycount := 0
	crtPath := ""
	keyPath := ""
	for _, v := range files {
		if strings.Contains(v.Name(), ".pem") {
			crtPath = path + "/" + v.Name()
			certcount++
		}
		if strings.Contains(v.Name(), ".key") {
			keycount++
			keyPath = path + "/" + v.Name()
		}
	}
	if certcount > 1 || keycount > 1 {
		logrus.WithField("Certificates", certcount).WithField("Keys", keycount).Error("More than one key/certificate present.")
		return CertPair{CertType: InvalidCert}
	}
	if keycount == 0 {
		logrus.Error("Missing key.")
		return CertPair{CertType: InvalidCert}
	}
	if certcount == 0 {
		logrus.Error("Missing Certificate.")
		return CertPair{CertType: InvalidCert}
	}
	pkey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		logrus.WithError(err).Error(`ioutil.ReadFile(` + keyPath + `)`)
		return CertPair{CertType: InvalidCert}
	}
	pblock, _ := pem.Decode(pkey)
	if x509.IsEncryptedPEMBlock(pblock) {
		if len(password) > 0 {
			phrase := strings.Join(password, " ")
			tmp, err := x509.DecryptPEMBlock(pblock, []byte(phrase))
			if err != nil {
				logrus.WithError(err).Error("Invalid password for private key.")
				return CertPair{CertType: InvalidCert}
			}
			pblock.Bytes = tmp
		} else {
			logrus.Error("Password for private key not provided.")
			return CertPair{CertType: InvalidCert}
		}
	}
	key, err := x509.ParseECPrivateKey(pblock.Bytes)
	if err != nil {
		logrus.WithError(err).Error(`x509.ParseECPrivateKey(pkey)`)
		return CertPair{CertType: InvalidCert}
	}
	dcert, err := ioutil.ReadFile(crtPath)
	if err != nil {
		logrus.WithError(err).Error(`ioutil.ReadFile(` + crtPath + `)`)
		return CertPair{CertType: InvalidCert}
	}
	cblock, _ := pem.Decode(dcert)
	cert, err := x509.ParseCertificate(cblock.Bytes)
	if err != nil {
		logrus.WithError(err).Error(`x509.ParseCertificate(cblock.Bytes)`)
		return CertPair{CertType: InvalidCert}
	}
	if !(*cert.PublicKey.(*ecdsa.PublicKey)).IsOnCurve(key.X, key.Y) {
		logrus.Error(keyPath, "does not match", crtPath)
		return CertPair{CertType: InvalidCert}
	}
	if cert.IsCA && cert.KeyUsage&x509.KeyUsageCertSign == x509.KeyUsageCertSign {
		return CertPair{
			cert:     cert,
			key:      key,
			CertType: CACert,
		}
	}
	if !cert.IsCA && cert.KeyUsage&x509.KeyUsageKeyEncipherment == x509.KeyUsageKeyEncipherment && cert.KeyUsage&x509.KeyUsageDigitalSignature == x509.KeyUsageDigitalSignature {
		return CertPair{
			cert:     cert,
			key:      key,
			CertType: ServerCert,
		}
	}
	if !cert.IsCA && cert.KeyUsage&x509.KeyUsageDigitalSignature == x509.KeyUsageDigitalSignature {
		return CertPair{
			cert:     cert,
			key:      key,
			CertType: ClientCert,
		}
	}
	return CertPair{CertType: InvalidCert}
}

func (p *CertPair) Validate(CA ...*CertPair) bool {
	if p.CertType == InvalidCert {
		return false
	}
	for idx := range CA {
		if err := p.cert.CheckSignatureFrom(CA[idx].cert); err != nil {
			logrus.WithError(err).Error("Certificate validation Failed")
			return false
		}
	}
	return true
}

func (p *CertPair) MustValidate(CA ...*CertPair) {
	if !p.Validate(CA...) {
		logrus.Fatal()
	}
}

func (p *CertPair) Save(path string, password ...string) error {
	keyOut := &bytes.Buffer{}
	certOut := &bytes.Buffer{}
	if pemErr := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: p.cert.Raw}); pemErr != nil {
		logrus.WithError(pemErr).Error(`pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})`)
		return pemErr
	}
	if pemErr := pem.Encode(keyOut, pemBlockForKey(p.key)); pemErr != nil {
		logrus.WithError(pemErr).Error(`pem.Encode(keyOut, pemBlockForKey(key))`)
		return pemErr
	}
	if len(password) != 0 {
		phrase := strings.Join(password, " ")
		keyPem_enc, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", pemBlockForKey(p.key).Bytes, []byte(phrase), x509.PEMCipherAES256)
		if err != nil {
			logrus.WithError(err).Error(`x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", keyPem.Bytes, []byte(phrase), x509.PEMCipherAES256)`)
			return err
		}
		keyOut.Reset()
		if pemErr := pem.Encode(keyOut, keyPem_enc); pemErr != nil {
			logrus.WithError(pemErr).Error(`pem.Encode(keyOut, pemBlockForKey(key))`)
			return pemErr
		}
	}
	if ioErr := ioutil.WriteFile(path+"/"+p.CertType.String()+".pem", certOut.Bytes(), 0600); ioErr != nil {
		logrus.WithError(ioErr).Error(`ioutil.WriteFile(` + path + "/" + p.CertType.String() + `.pem", certOut.Bytes(), 0600);`)
		return ioErr
	}
	if ioErr := ioutil.WriteFile(path+"/"+p.CertType.String()+".key", keyOut.Bytes(), 0600); ioErr != nil {
		logrus.WithError(ioErr).Error(`ioutil.WriteFile(` + path + "/" + p.CertType.String() + `.key", certOut.Bytes(), 0600);`)
		return ioErr
	}
	certOut.Reset()
	keyOut.Reset()
	return nil
}

// taken from https://gist.github.com/samuel/8b500ddd3f6118d052b5e6bc16bc4c09

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func genPrivateKey(c elliptic.Curve) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		logrus.WithError(err).Fatal(`genPrivateKey()...cdsa.GenerateKey()`)
	}
	return key
}

func genSerialNumber() *big.Int {
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logrus.WithError(err).Fatal(`genSerialNumber() .. rand.Int()`)
	}
	return serialNumber
}

func genCA(rootKey *ecdsa.PrivateKey) (cert *x509.Certificate) {
	derBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, publicKey(rootKey), rootKey)
	if err != nil {
		logrus.WithError(err).Fatal(`x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)`)
	}
	cacert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		logrus.WithError(err).Fatal(`x509.ParseCertificate(derBytes)`)
	}
	return cacert
}

func genCert(privKey *ecdsa.PrivateKey, template *x509.Certificate, CA *x509.Certificate, CAKey *ecdsa.PrivateKey) (cert *x509.Certificate) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, CA, publicKey(privKey), CAKey)
	if err != nil {
		logrus.WithError(err).Fatal(`x509.CreateCertificate(rand.Reader, template, CA, publicKey(privKey), CAKey)`)
	}
	cert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		logrus.WithError(err).Fatal(`x509.ParseCertificate(derBytes)`)
	}
	if verifyCert(template, cert, privKey, CA) {
		return cert
	}
	return nil
}

func verifyCert(template *x509.Certificate, cert *x509.Certificate, key *ecdsa.PrivateKey, CA *x509.Certificate) bool {
	if !(*cert.PublicKey.(*ecdsa.PublicKey)).IsOnCurve(key.X, key.Y) {
		logrus.Error("Private Key does not match Certificate.")
		return false
	}
	if err := cert.CheckSignatureFrom(CA); err != nil {
		logrus.Error("Certificate not signed by provided CA.")
		return false
	}
	if template != nil {
		if !cert.NotAfter.Equal(template.NotAfter) {
			logrus.Error("Certificate NotAfter does not match template")
		}
		if cert.Subject.CommonName != template.Subject.CommonName {
			logrus.Error("Certificate CommonName does not match template")
		}
		if !reflect.DeepEqual(cert.Subject.Organization, template.Subject.Organization) {
			logrus.Error("Certificate Organization does not match template")
		}
		if !reflect.DeepEqual(cert.Subject.OrganizationalUnit, template.Subject.OrganizationalUnit) {
			logrus.Error("Certificate OrganizationalUnit does not match template")
		}
	}
	return true
}

func findCerts(ctype string) (out []string) {
	servers, err := ioutil.ReadDir("./certs/" + ctype)
	if err != nil {
		logrus.WithError(err).Fatal("./certs missing.")
	}
	for _, f := range servers {
		if f.IsDir() {
			logrus.Info(f.Name())
			out = append(out, "./certs/"+ctype+"/"+f.Name())
		}
	}
	return out
}

func readConfig(filename string, defaults map[string]interface{}) (*viper.Viper, error) {
	v := viper.New()
	for k, val := range defaults {
		v.SetDefault(k, val)
	}
	v.SetConfigName(filename)
	v.AddConfigPath(".")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetTypeByDefaultValue(true)
	err := v.ReadInConfig()
	if err != nil {
		switch err.(type) {
		case viper.ConfigFileNotFoundError:
			logrus.WithError(err).Warn("Config file not found. Generating default config.")
			tmp := viper.New()
			for k, v := range defaults {
				tmp.Set(k, v)
			}
			if err := tmp.WriteConfigAs(configfile + ".json"); err != nil {
				logrus.WithError(err).Fatal("Unable to write default config")
			}
			return v, nil
		}
	}
	return v, err
}

func loadCA() (*x509.Certificate, *ecdsa.PrivateKey) {
	verifyCA()
	logrus.Info("Verify CA.key match CA.pem")
	pkey, err := ioutil.ReadFile(CAPATH + "CA.key")
	if err != nil {
		logrus.WithError(err).Fatal(`ioutil.ReadFile(CAPATH+"CA.key")`)
	}
	pblock, _ := pem.Decode(pkey)
	key, err := x509.ParseECPrivateKey(pblock.Bytes)
	if err != nil {
		logrus.WithError(err).Fatal(`x509.ParseECPrivateKey(pkey)`)
	}
	dcert, err := ioutil.ReadFile(CAPATH + "CA.pem")
	if err != nil {
		logrus.WithError(err).Fatal(`ioutil.ReadFile(CAPATH+"CA.pem")`)
	}
	cblock, _ := pem.Decode(dcert)
	cert, err := x509.ParseCertificate(cblock.Bytes)
	if err != nil {
		logrus.WithError(err).Fatal(`x509.ParseCertificate(cblock.Bytes)`)
	}
	if !(*cert.PublicKey.(*ecdsa.PublicKey)).IsOnCurve(key.X, key.Y) {
		logrus.Fatal("CA.pem does not match CA.key")
	}
	if !cert.NotAfter.Equal(rootTemplate.NotAfter) {
		logrus.Fatal("CA cert NotAfter does not match config file.")
	}
	if cert.Subject.CommonName != rootTemplate.Subject.CommonName {
		logrus.Fatal("CA cert CommonName does not match config file.")
	}
	if !reflect.DeepEqual(cert.Subject.Organization, rootTemplate.Subject.Organization) {
		logrus.Fatal("CA cert Organization does not match config file.")
	}
	if !reflect.DeepEqual(cert.Subject.OrganizationalUnit, rootTemplate.Subject.OrganizationalUnit) {
		logrus.Fatal("CA cert OrganizationalUnit does not match config file.")
	}
	return cert, key
}

func verifyCA() {
	if err := os.MkdirAll(CAPATH, 0700); err != nil {
		logrus.WithError(err).Fatal(`os.MkdirAll(CAPATH, 0600)`)
	}
	if err := os.MkdirAll(SERVERPATH, 0700); err != nil {
		logrus.WithError(err).Fatal(`os.MkdirAll(SERVERPATH, 0600)`)
	}
	if err := os.MkdirAll(CLIENTPATH, 0700); err != nil {
		logrus.WithError(err).Fatal(`os.MkdirAll(CLIENTPATH, 0600)`)
	}
	if _, err := os.Stat(CAPATH + "CA.key"); os.IsNotExist(err) {
		logrus.Info("Generating CA.key")
		key := genPrivateKey(elliptic.P256())
		keyOut := &bytes.Buffer{}
		if pemErr := pem.Encode(keyOut, pemBlockForKey(key)); pemErr != nil {
			logrus.WithError(pemErr).Fatal(`pem.Encode(keyOut, pemBlockForKey(key))`)
		}
		if ioErr := ioutil.WriteFile(CAPATH+"CA.key", keyOut.Bytes(), 0600); ioErr != nil {
			logrus.WithError(ioErr).Fatal(`ioutil.WriteFile(CAPATH+"CA.key", keyOut.Bytes(), 0600)`)
		}
		keyOut.Reset()
		logrus.Info("Generating CA.pem")
		cert := genCA(key)
		certOut := &bytes.Buffer{}
		if pemErr := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); pemErr != nil {
			logrus.WithError(pemErr).Fatal(`pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})`)
		}
		if ioErr := ioutil.WriteFile(CAPATH+"CA.pem", certOut.Bytes(), 0600); ioErr != nil {
			logrus.WithError(ioErr).Fatal(`ioutil.WriteFile(CAPATH+"CA.pem", certOut.Bytes(), 0600);`)
		}
		certOut.Reset()
		if !(*cert.PublicKey.(*ecdsa.PublicKey)).IsOnCurve(key.X, key.Y) {
			logrus.Fatal("CA.pem doesnt not match CA.key")
		}
		return
	}
	if _, err := os.Stat(CAPATH + "CA.pem"); os.IsNotExist(err) {
		logrus.Info("Found CA.key, but no CA.pem. Generating CA.pem")
		pkey, err := ioutil.ReadFile(CAPATH + "CA.key")
		if err != nil {
			logrus.WithError(err).Fatal(`ioutil.ReadFile(CAPATH+"CA.key")`)
		}
		pblock, _ := pem.Decode(pkey)
		key, err := x509.ParseECPrivateKey(pblock.Bytes)
		if err != nil {
			logrus.WithError(err).Fatal(`x509.ParseECPrivateKey(pkey)`)
		}
		cert := genCA(key)
		certOut := &bytes.Buffer{}
		if pemErr := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); pemErr != nil {
			logrus.WithError(pemErr).Fatal(`pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})`)
		}
		if ioErr := ioutil.WriteFile(CAPATH+"CA.pem", certOut.Bytes(), 0600); ioErr != nil {
			logrus.WithError(ioErr).Fatal(`ioutil.WriteFile(CAPATH+"CA.pem", certOut.Bytes(), 0600);`)
		}
		certOut.Reset()
		if !(*cert.PublicKey.(*ecdsa.PublicKey)).IsOnCurve(key.X, key.Y) {
			logrus.Fatal("CA.pem doesnt not match CA.key")
		}
		return
	}
}

func loadServer(CA *x509.Certificate, CAKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	verifyServer(CA, CAKey)
	logrus.Info("Verify Server.key match Server.pem")
	pkey, err := ioutil.ReadFile(SERVERPATH + "Server.key")
	if err != nil {
		logrus.WithError(err).Fatal(`ioutil.ReadFile(SERVERPATH+"Server.key")`)
	}
	pblock, _ := pem.Decode(pkey)
	key, err := x509.ParseECPrivateKey(pblock.Bytes)
	if err != nil {
		logrus.WithError(err).Fatal(`x509.ParseECPrivateKey(pkey)`)
	}
	dcert, err := ioutil.ReadFile(SERVERPATH + "Server.pem")
	if err != nil {
		logrus.WithError(err).Fatal(`ioutil.ReadFile(SERVERPATH+"Server.pem")`)
	}
	cblock, _ := pem.Decode(dcert)
	cert, err := x509.ParseCertificate(cblock.Bytes)
	if err != nil {
		logrus.WithError(err).Fatal(`x509.ParseCertificate(cblock.Bytes)`)
	}
	if !(*cert.PublicKey.(*ecdsa.PublicKey)).IsOnCurve(key.X, key.Y) {
		logrus.Fatal("Server.pem does not match Server.key")
	}
	logrus.Info("Verify Server.pem signed by CA")
	if err := cert.CheckSignatureFrom(CA); err != nil {
		logrus.WithError(err).Fatal("Verify Signature.")
	}
	if !cert.NotAfter.Equal(serverTemplate.NotAfter) {
		logrus.Fatal("Server cert NotAfter does not match config file.")
	}
	if cert.Subject.CommonName != serverTemplate.Subject.CommonName {
		logrus.Fatal("Server cert CommonName does not match config file.")
	}
	if !reflect.DeepEqual(cert.Subject.Organization, serverTemplate.Subject.Organization) {
		logrus.Fatal("Server cert Organization does not match config file.")
	}
	if !reflect.DeepEqual(cert.Subject.OrganizationalUnit, serverTemplate.Subject.OrganizationalUnit) {
		logrus.Fatal("Server cert OrganizationalUnit does not match config file.")
	}
	return cert, key
}

func verifyServer(CA *x509.Certificate, CAKey *ecdsa.PrivateKey) {
	if err := os.MkdirAll(CAPATH, 0700); err != nil {
		logrus.WithError(err).Fatal(`os.MkdirAll(CAPATH, 0600)`)
	}
	if err := os.MkdirAll(SERVERPATH, 0700); err != nil {
		logrus.WithError(err).Fatal(`os.MkdirAll(SERVERPATH, 0600)`)
	}
	if err := os.MkdirAll(CLIENTPATH, 0700); err != nil {
		logrus.WithError(err).Fatal(`os.MkdirAll(CLIENTPATH, 0600)`)
	}
	if _, err := os.Stat(SERVERPATH + "Server.key"); os.IsNotExist(err) {
		logrus.Info("Generating Server.key")
		key := genPrivateKey(elliptic.P256())
		keyOut := &bytes.Buffer{}
		if pemErr := pem.Encode(keyOut, pemBlockForKey(key)); pemErr != nil {
			logrus.WithError(pemErr).Fatal(`pem.Encode(keyOut, pemBlockForKey(key))`)
		}
		if ioErr := ioutil.WriteFile(SERVERPATH+"Server.key", keyOut.Bytes(), 0600); ioErr != nil {
			logrus.WithError(ioErr).Fatal(`ioutil.WriteFile(SERVERPATH+"Server.key", keyOut.Bytes(), 0600)`)
		}
		keyOut.Reset()
		logrus.Info("Generating Server.pem")
		cert := genCert(key, &serverTemplate, CA, CAKey)
		certOut := &bytes.Buffer{}
		if pemErr := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); pemErr != nil {
			logrus.WithError(pemErr).Fatal(`pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})`)
		}
		if ioErr := ioutil.WriteFile(SERVERPATH+"Server.pem", certOut.Bytes(), 0600); ioErr != nil {
			logrus.WithError(ioErr).Fatal(`ioutil.WriteFile(SERVERPATH+"Server.pem", certOut.Bytes(), 0600);`)
		}
		certOut.Reset()
		if !(*cert.PublicKey.(*ecdsa.PublicKey)).IsOnCurve(key.X, key.Y) {
			logrus.Fatal("Server.pem doesnt not match Server.key")
		}
	}
	if _, err := os.Stat(SERVERPATH + "Server.pem"); os.IsNotExist(err) {
		logrus.Info("Found Server.key, but no Server.pem. Generating Server.pem")
		pkey, err := ioutil.ReadFile(SERVERPATH + "Server.key")
		if err != nil {
			logrus.WithError(err).Fatal(`ioutil.ReadFile(SERVERPATH + "Server.key")`)
		}
		pblock, _ := pem.Decode(pkey)
		key, err := x509.ParseECPrivateKey(pblock.Bytes)
		if err != nil {
			logrus.WithError(err).Fatal(`x509.ParseECPrivateKey(pkey)`)
		}
		cert := genCert(key, &serverTemplate, CA, CAKey)
		certOut := &bytes.Buffer{}
		if pemErr := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); pemErr != nil {
			logrus.WithError(pemErr).Fatal(`pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})`)
		}
		if ioErr := ioutil.WriteFile(SERVERPATH+"Server.pem", certOut.Bytes(), 0600); ioErr != nil {
			logrus.WithError(ioErr).Fatal(`ioutil.WriteFile(SERVERPATH+"Server.pem", certOut.Bytes(), 0600);`)
		}
		certOut.Reset()
		if !(*cert.PublicKey.(*ecdsa.PublicKey)).IsOnCurve(key.X, key.Y) {
			logrus.Fatal("Server.pem doesnt not match Server.key")
		}
		return
	}
}

func loadClient(CA *x509.Certificate, CAKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	verifyClient(CA, CAKey)
	logrus.Info("Verify Client.key match Client.pem")
	pkey, err := ioutil.ReadFile(CLIENTPATH + "Client.key")
	if err != nil {
		logrus.WithError(err).Fatal(`ioutil.ReadFile(CLIENTPATH+"Client.key")`)
	}
	pblock, _ := pem.Decode(pkey)
	key, err := x509.ParseECPrivateKey(pblock.Bytes)
	if err != nil {
		logrus.WithError(err).Fatal(`x509.ParseECPrivateKey(pkey)`)
	}
	dcert, err := ioutil.ReadFile(CLIENTPATH + "Client.pem")
	if err != nil {
		logrus.WithError(err).Fatal(`ioutil.ReadFile(CLIENTPATH+"Client.pem")`)
	}
	cblock, _ := pem.Decode(dcert)
	cert, err := x509.ParseCertificate(cblock.Bytes)
	if err != nil {
		logrus.WithError(err).Fatal(`x509.ParseCertificate(cblock.Bytes)`)
	}
	if !(*cert.PublicKey.(*ecdsa.PublicKey)).IsOnCurve(key.X, key.Y) {
		logrus.Fatal("Client.pem does not match Client.key")
	}
	logrus.Info("Verify Client.pem signed by CA")
	if err := cert.CheckSignatureFrom(CA); err != nil {
		logrus.WithError(err).Fatal("Verify Signature.")
	}
	if !cert.NotAfter.Equal(clientTemplate.NotAfter) {
		logrus.Fatal("Client cert NotAfter does not match config file.")
	}
	if cert.Subject.CommonName != clientTemplate.Subject.CommonName {
		logrus.Fatal("Client cert CommonName does not match config file.")
	}
	if !reflect.DeepEqual(cert.Subject.Organization, clientTemplate.Subject.Organization) {
		logrus.Fatal("Client cert Organization does not match config file.")
	}
	if !reflect.DeepEqual(cert.Subject.OrganizationalUnit, clientTemplate.Subject.OrganizationalUnit) {
		logrus.Fatal("Client cert OrganizationalUnit does not match config file.")
	}
	return cert, key
}

func verifyClient(CA *x509.Certificate, CAKey *ecdsa.PrivateKey) {
	if err := os.MkdirAll(CAPATH, 0700); err != nil {
		logrus.WithError(err).Fatal(`os.MkdirAll(CAPATH, 0600)`)
	}
	if err := os.MkdirAll(SERVERPATH, 0700); err != nil {
		logrus.WithError(err).Fatal(`os.MkdirAll(SERVERPATH, 0600)`)
	}
	if err := os.MkdirAll(CLIENTPATH, 0700); err != nil {
		logrus.WithError(err).Fatal(`os.MkdirAll(CLIENTPATH, 0600)`)
	}
	if _, err := os.Stat(CLIENTPATH + "Client.key"); os.IsNotExist(err) {
		logrus.Info("Generating Client.key")
		key := genPrivateKey(elliptic.P256())
		keyOut := &bytes.Buffer{}
		if pemErr := pem.Encode(keyOut, pemBlockForKey(key)); pemErr != nil {
			logrus.WithError(pemErr).Fatal(`pem.Encode(keyOut, pemBlockForKey(key))`)
		}
		if ioErr := ioutil.WriteFile(CLIENTPATH+"Client.key", keyOut.Bytes(), 0600); ioErr != nil {
			logrus.WithError(ioErr).Fatal(`ioutil.WriteFile(CLIENTPATH+"Client.key", keyOut.Bytes(), 0600)`)
		}
		keyOut.Reset()
		logrus.Info("Generating Client.pem")
		cert := genCert(key, &clientTemplate, CA, CAKey)
		certOut := &bytes.Buffer{}
		if pemErr := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); pemErr != nil {
			logrus.WithError(pemErr).Fatal(`pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})`)
		}
		if ioErr := ioutil.WriteFile(CLIENTPATH+"Client.pem", certOut.Bytes(), 0600); ioErr != nil {
			logrus.WithError(ioErr).Fatal(`ioutil.WriteFile(CLIENTPATH+"Client.pem", certOut.Bytes(), 0600);`)
		}
		certOut.Reset()
		if !(*cert.PublicKey.(*ecdsa.PublicKey)).IsOnCurve(key.X, key.Y) {
			logrus.Fatal("Client.pem doesnt not match Client.key")
		}
	}
	if _, err := os.Stat(CLIENTPATH + "Client.pem"); os.IsNotExist(err) {
		logrus.Info("Found Client.key, but no Client.pem. Generating Client.pem")
		pkey, err := ioutil.ReadFile(CLIENTPATH + "Client.key")
		if err != nil {
			logrus.WithError(err).Fatal(`ioutil.ReadFile(CLIENTPATH + "Client.key")`)
		}
		pblock, _ := pem.Decode(pkey)
		key, err := x509.ParseECPrivateKey(pblock.Bytes)
		if err != nil {
			logrus.WithError(err).Fatal(`x509.ParseECPrivateKey(pkey)`)
		}
		cert := genCert(key, &clientTemplate, CA, CAKey)
		certOut := &bytes.Buffer{}
		if pemErr := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); pemErr != nil {
			logrus.WithError(pemErr).Fatal(`pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})`)
		}
		if ioErr := ioutil.WriteFile(CLIENTPATH+"Client.pem", certOut.Bytes(), 0600); ioErr != nil {
			logrus.WithError(ioErr).Fatal(`ioutil.WriteFile(CLIENTPATH+"Client.pem", certOut.Bytes(), 0600);`)
		}
		certOut.Reset()
		if !(*cert.PublicKey.(*ecdsa.PublicKey)).IsOnCurve(key.X, key.Y) {
			logrus.Fatal("Client.pem doesnt not match Client.key")
		}
		return
	}
}

func main() {
	vconf, err := readConfig(configfile, map[string]interface{}{
		"ca": map[string]interface{}{
			"org":      "ldbgrpc",
			"cn":       "Root CA",
			"notafter": time.Now().Add(time.Hour * 24 * 3650).Truncate(time.Second).String(),
		},
		"server": map[string]interface{}{
			"org": "ldbgrpc",
			"cn":  "Server Certificate",
			"ou": []string{
				"GRPC Server",
			},
			"notafter": time.Now().Add(time.Hour * 24 * 365).Truncate(time.Second).String(),
			"host": []string{
				"localhost",
			},
			"ips": []net.IP{
				net.ParseIP("127.0.0.1"),
			},
		},
		"client": map[string]interface{}{
			"org": "ldbgrpc",
			"cn":  "Client Certificate",
			"ou": []string{
				"GRPC Client",
			},
			"notafter": time.Now().Add(time.Hour * 24 * 365).Truncate(time.Second).String(),
		},
	})
	if err != nil {
		logrus.WithError(err).Fatal("Config parse error")
	}
	//Configure CA tempalte
	rootTemplate.Subject = pkix.Name{
		Organization: []string{vconf.GetString("ca.org")},
		CommonName:   vconf.GetString("ca.cn"),
	}
	rootTemplate.NotAfter = vconf.GetTime("ca.notafter")

	//Configure server certificate template
	serverTemplate.Subject = pkix.Name{
		Organization:       []string{vconf.GetString("server.org")},
		CommonName:         vconf.GetString("server.cn"),
		OrganizationalUnit: vconf.GetStringSlice("server.ou"),
	}
	serverTemplate.NotAfter = vconf.GetTime("server.notafter")
	serverTemplate.DNSNames = vconf.GetStringSlice("server.host")
	ips := []net.IP{}
	for _, v := range vconf.GetStringSlice("server.ips") {
		ips = append(ips, net.ParseIP(v))
	}
	serverTemplate.IPAddresses = ips

	//Configure client certificate tempalte

	clientTemplate.Subject = pkix.Name{
		Organization:       []string{vconf.GetString("client.org")},
		CommonName:         vconf.GetString("client.cn"),
		OrganizationalUnit: vconf.GetStringSlice("client.ou"),
	}
	clientTemplate.NotAfter = vconf.GetTime("client.notafter")

	//load ROOT CA
	cacert, cakey := loadCA()
	_, _ = loadServer(cacert, cakey)
	_, _ = loadClient(cacert, cakey)
	fmt.Println(findCerts("SERVER"))
	fmt.Println(findCerts("CLIENT"))
	CAPair := CertLoad("./certs/CA")
	CAPair.MustValidate()
	spew.Dump(CAPair)
}

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
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	CERTPATH          = "certs/"
	CAPATH            = CERTPATH + "CA/"
	SERVERPATH        = CERTPATH + "SERVER/"
	CLIENTPATH        = CERTPATH + "CLIENT/"
	serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
	rootTemplate      = x509.Certificate{
		SerialNumber: genSerialNumber(),
		Subject: pkix.Name{
			Organization: []string{"ldbgrpc"},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 3650),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
)

func init() {
	logrus.SetReportCaller(true)
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

func main() {
	cacert, cakey := loadCA()
	fmt.Println(cacert, cakey)
	return
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logrus.WithError(err).Fatal(`cdsa.GenerateKey(elliptic.P521(), rand.Reader)`)
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logrus.WithError(err).Fatal(`cdsa.GenerateKey(elliptic.P521(), rand.Reader)`)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logrus.WithError(err).Fatal(`cdsa.GenerateKey(elliptic.P521(), rand.Reader)`)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logrus.WithError(err).Fatal(`rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))`)
	}

	rootTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ldbgrpc"},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 3650),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		logrus.WithError(err).Fatal(`x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)`)
	}
	rootOut := &bytes.Buffer{}
	pem.Encode(rootOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	ioutil.WriteFile("certs/CA.pem", rootOut.Bytes(), 0600)
	rootOut.Reset()
	pem.Encode(rootOut, pemBlockForKey(rootKey))
	ioutil.WriteFile("certs/CA.key", rootOut.Bytes(), 0600)

	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logrus.WithError(err).Fatal(`rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))`)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ldbgroc"},
			CommonName:   "Server Certificate",
		},
		DNSNames: []string{"localhost", "cache.credoweb.io", "ldbgrpc"},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv4(192, 168, 11, 62),
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 3650),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err = x509.CreateCertificate(rand.Reader, &template, &rootTemplate, &priv.PublicKey, rootKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	ioutil.WriteFile("certs/server.crt", out.Bytes(), 0600)
	out.Reset()
	pem.Encode(out, pemBlockForKey(priv))
	ioutil.WriteFile("certs/server.key", out.Bytes(), 0600)

	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logrus.WithError(err).Fatal(`rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))`)
	}

	clientTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ldbgroc"},
			CommonName:   "client certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 3650),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err = x509.CreateCertificate(rand.Reader, &clientTemplate, &rootTemplate, &clientKey.PublicKey, rootKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	clientOut := &bytes.Buffer{}
	pem.Encode(clientOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	ioutil.WriteFile("certs/client.crt", clientOut.Bytes(), 0600)
	clientOut.Reset()
	pem.Encode(clientOut, pemBlockForKey(clientKey))
	ioutil.WriteFile("certs/client.key", clientOut.Bytes(), 0600)
}

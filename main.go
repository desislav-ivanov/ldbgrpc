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

func main() {
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

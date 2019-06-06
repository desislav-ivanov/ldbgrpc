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

	"github.com/spf13/cobra"
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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	serverTemplate = x509.Certificate{
		SerialNumber:          genSerialNumber(),
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
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

var CAPair *CertPair
var DefaultServer *CertPair
var DefaultClient *CertPair

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

func CertLoad(path string, password ...string) *CertPair {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		logrus.WithError(err).Error("Unable to read " + path)
		return nil
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
		return nil
	}
	if keycount == 0 {
		logrus.Error("Missing key.")
		return nil
	}
	if certcount == 0 {
		logrus.Error("Missing Certificate.")
		return nil
	}
	pkey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		logrus.WithError(err).Error(`ioutil.ReadFile(` + keyPath + `)`)
		return nil
	}
	pblock, _ := pem.Decode(pkey)
	if x509.IsEncryptedPEMBlock(pblock) {
		if len(password) > 0 {
			phrase := strings.Join(password, " ")
			tmp, err := x509.DecryptPEMBlock(pblock, []byte(phrase))
			if err != nil {
				logrus.WithError(err).Error("Invalid password for private key.")
				return nil
			}
			pblock.Bytes = tmp
		} else {
			logrus.Error("Password for private key not provided.")
			return nil
		}
	}
	key, err := x509.ParseECPrivateKey(pblock.Bytes)
	if err != nil {
		logrus.WithError(err).Error(`x509.ParseECPrivateKey(pkey)`)
		return nil
	}
	dcert, err := ioutil.ReadFile(crtPath)
	if err != nil {
		logrus.WithError(err).Error(`ioutil.ReadFile(` + crtPath + `)`)
		return nil
	}
	cblock, _ := pem.Decode(dcert)
	cert, err := x509.ParseCertificate(cblock.Bytes)
	if err != nil {
		logrus.WithError(err).Error(`x509.ParseCertificate(cblock.Bytes)`)
		return nil
	}
	if !(*cert.PublicKey.(*ecdsa.PublicKey)).IsOnCurve(key.X, key.Y) {
		logrus.Error(keyPath, "does not match", crtPath)
		return nil
	}
	if cert.IsCA && cert.KeyUsage&x509.KeyUsageCertSign == x509.KeyUsageCertSign {
		return &CertPair{
			cert:     cert,
			key:      key,
			CertType: CACert,
		}
	}
	if !cert.IsCA && cert.KeyUsage&x509.KeyUsageKeyEncipherment == x509.KeyUsageKeyEncipherment && cert.KeyUsage&x509.KeyUsageDigitalSignature == x509.KeyUsageDigitalSignature {
		return &CertPair{
			cert:     cert,
			key:      key,
			CertType: ServerCert,
		}
	}
	if !cert.IsCA && cert.KeyUsage&x509.KeyUsageDigitalSignature == x509.KeyUsageDigitalSignature {
		return &CertPair{
			cert:     cert,
			key:      key,
			CertType: ClientCert,
		}
	}
	return nil
}

func CertGen(gentype CertType, template *x509.Certificate, CAPair ...*CertPair) *CertPair {
	var cert *x509.Certificate
	key := genPrivateKey(elliptic.P256())
	switch gentype {
	case CACert:
		cert = genCert(key, template, template, key)
		return &CertPair{
			cert:     cert,
			key:      key,
			CertType: gentype,
		}
	case ServerCert, ClientCert:
		if len(CAPair) == 1 {
			cert = genCert(key, template, CAPair[0].cert, CAPair[0].key)
			return &CertPair{
				cert:     cert,
				key:      key,
				CertType: gentype,
			}
		}
	default:
		return nil
	}
	return nil
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
	if err := os.MkdirAll(path, 0700); err != nil {
		logrus.WithError(err).Fatal(`os.MkdirAll(` + path + `, 0600)`)
	}
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
	logrus.Info("Certificate and Key saved at ", path)
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

func genCert(privKey *ecdsa.PrivateKey, template *x509.Certificate, CA *x509.Certificate, CAKey *ecdsa.PrivateKey) (cert *x509.Certificate) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, CA, publicKey(privKey), CAKey)
	if err != nil {
		logrus.WithError(err).Fatal(`x509.CreateCertificate(rand.Reader, template, CA, publicKey(privKey), CAKey)`)
	}
	cert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		logrus.WithError(err).Fatal(`x509.ParseCertificate(derBytes)`)
	}
	if template.Equal(CA) {
		logrus.Info("Verifying Self-Signed Certificate.")
		if verifyCert(template, cert, privKey, cert) {
			return cert
		}
	} else {
		logrus.Info("Verifying CA-Signed Certificate.")
		if verifyCert(template, cert, privKey, CA) {
			return cert
		}
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
		if f.IsDir() && f.Name() != "default" {
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
			if err := tmp.WriteConfigAs(configfile + ".yaml"); err != nil {
				logrus.WithError(err).Fatal("Unable to write default config")
			}
			return v, nil
		}
	}
	return v, err
}

//COBRA configuration

var rootCmd = &cobra.Command{
	Use:   "certmanager",
	Short: "certmanager is Certificate generator targeted for ldbgrpc",
	Long: `
	certmanager is "self-signed CA" Certificate manager.
	it can generate server and client certificates.
	`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {

		//Generate defaults if faulty or non existent
		CAPair = CertLoad(CAPATH)
		if CAPair == nil || !CAPair.Validate() {
			logrus.Warn("Generate new master CA from config.")
			CAPair = CertGen(CACert, &rootTemplate)
			if err := CAPair.Save(CAPATH); err != nil {
				logrus.WithError(err).Fatal("Unable to create master CA")
			}
		}
		DefaultServer = CertLoad(SERVERPATH + "default")
		if DefaultServer == nil || !DefaultServer.Validate(CAPair) {
			logrus.Warn("Generate new Default Server Certificate from config.")
			DefaultServer = CertGen(ServerCert, &serverTemplate, CAPair)
			if err := DefaultServer.Save(SERVERPATH + "default"); err != nil {
				logrus.WithError(err).Fatal("Unable to create Default Server Certificate")
			}
		}
		DefaultClient = CertLoad(CLIENTPATH + "default")
		if DefaultClient == nil || !DefaultClient.Validate(CAPair) {
			logrus.Warn("Generate new Default Client Certificate from config.")
			DefaultClient = CertGen(ClientCert, &clientTemplate, CAPair)
			if err := DefaultClient.Save(CLIENTPATH + "default"); err != nil {
				logrus.WithError(err).Fatal("Unable to create Default Server Certificate")
			}
		}
		CAPair.MustValidate(CAPair)
		DefaultServer.MustValidate(CAPair)
		DefaultClient.MustValidate(CAPair)
	},
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Prints the version number of certmanager",
	Long:  "Prints the version number of certmanager",
	Run: func(cmd *cobra.Command, args []string) {
		logrus.Print("v0.0.1")
	},
}

var validateServer bool
var validateClient bool
var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "validate generated certificates (always validates CA)",
	Long:  "use this command to validate the certificates you have generated\nnote that CA certificates are always validated.",
	Run: func(cmd *cobra.Command, args []string) {
		if !validateServer && !validateClient {
			_ = cmd.Help()
			return
		}
		if validateServer {
			for _, p := range findCerts("SERVER") {
				if !CertLoad(p).Validate(CAPair) {
					logrus.Warn(p, "Invalid Certificates")
					continue
				}
				logrus.Info(p, " OK")
			}
		}
		if validateClient {
			for _, p := range findCerts("CLIENT") {
				if !CertLoad(p).Validate(CAPair) {
					logrus.Warn(p, "Invalid Certificates")
					continue
				}
				logrus.Info(p, " OK")
			}
		}
	},
}

var generateCMD = &cobra.Command{
	Use:   "generate",
	Short: "generate new certificate from CA",
	Long:  "generate new certificate from CA",
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

var serverHostnamesVar []string
var serverIPsVar []net.IP
var serverValidNotAfterVar time.Duration
var serverCN string
var serverOrg []string
var serverOU []string
var serverCertName string
var generateServerCMD = &cobra.Command{
	Use:   "server",
	Short: "generate server certificate and key",
	Long:  "generate server certificate and key",
	Run: func(cmd *cobra.Command, args []string) {
		template := x509.Certificate(serverTemplate)
		template.Subject.Organization = serverOrg
		template.Subject.CommonName = serverCN
		template.Subject.OrganizationalUnit = serverOU
		template.NotAfter = time.Now().Add(serverValidNotAfterVar).Truncate(time.Second)
		template.DNSNames = serverHostnamesVar
		template.IPAddresses = serverIPsVar
		certPair := CertGen(ServerCert, &template, CAPair)
		if certPair.Validate(CAPair) {
			if err := certPair.Save(SERVERPATH + serverCertName); err != nil {
				logrus.WithError(err).Fatal("Certificate could not be saved.")
			}
		}
	},
}

var clientValidNotAfterVar time.Duration
var clientCN string
var clientOrg []string
var clientOU []string
var clientCertName string
var generateClientCMD = &cobra.Command{
	Use:   "client",
	Short: "generate client certificate and key",
	Long:  "generate client certificate and key",
	Run: func(cmd *cobra.Command, args []string) {
		template := x509.Certificate(clientTemplate)
		template.Subject.Organization = clientOrg
		template.Subject.CommonName = clientCN
		template.Subject.OrganizationalUnit = clientOU
		template.NotAfter = time.Now().Add(clientValidNotAfterVar).Truncate(time.Second)
		certPair := CertGen(ClientCert, &template, CAPair)
		if certPair.Validate(CAPair) {
			if err := certPair.Save(CLIENTPATH + clientCertName); err != nil {
				logrus.WithError(err).Fatal("Certificate could not be saved.")
			}
		}
	},
}

func setupViper() {
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
				"ldbgrpc",
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

	//Configure default server certificate template
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

	//Configure default client certificate tempalte

	clientTemplate.Subject = pkix.Name{
		Organization:       []string{vconf.GetString("client.org")},
		CommonName:         vconf.GetString("client.cn"),
		OrganizationalUnit: vconf.GetStringSlice("client.ou"),
	}
	clientTemplate.NotAfter = vconf.GetTime("client.notafter")
}

func setupDirs() {
	if err := os.MkdirAll(CAPATH, 0700); err != nil {
		logrus.WithError(err).Fatal(`os.MkdirAll(CAPATH, 0600)`)
	}
	if err := os.MkdirAll(SERVERPATH, 0700); err != nil {
		logrus.WithError(err).Fatal(`os.MkdirAll(SERVERPATH, 0600)`)
	}
	if err := os.MkdirAll(CLIENTPATH, 0700); err != nil {
		logrus.WithError(err).Fatal(`os.MkdirAll(CLIENTPATH, 0600)`)
	}
}

func init() {
	setupDirs()
	setupViper()
	cobra.EnableCommandSorting = true
	cobra.EnablePrefixMatching = true
	rootCmd.AddCommand(versionCmd)
	//validate command
	validateCmd.Flags().BoolVarP(&validateServer, "server", "s", false, "validates all server certificates")
	validateCmd.Flags().BoolVarP(&validateClient, "client", "c", false, "validates all client certificates")
	rootCmd.AddCommand(validateCmd)
	//generate command
	//generate server command
	generateServerCMD.Flags().StringSliceVarP(&serverHostnamesVar, "dnsnames", "", []string{"localhost"}, "Subject Alternate Name")
	generateServerCMD.Flags().IPSliceVarP(&serverIPsVar, "ips", "", serverTemplate.IPAddresses, "IPAddress for Server Certificate")
	generateServerCMD.Flags().DurationVarP(&serverValidNotAfterVar, "NotAfter", "", time.Hour*24*365, "Duration for certificate validity")
	generateServerCMD.Flags().StringVarP(&serverCN, "CN", "", serverTemplate.Subject.CommonName, "Subject.CommonName")
	generateServerCMD.Flags().StringSliceVarP(&serverOrg, "Org", "", serverTemplate.Subject.Organization, "Subject.Organization")
	generateServerCMD.Flags().StringSliceVarP(&serverOU, "OU", "", serverTemplate.Subject.OrganizationalUnit, "Subject.OU")
	generateServerCMD.Flags().StringVarP(&serverCertName, "name", "n", "", "name for server certificate")
	generateServerCMD.MarkFlagRequired("name")
	generateCMD.AddCommand(generateServerCMD)
	//generate client command
	generateClientCMD.Flags().DurationVarP(&clientValidNotAfterVar, "NotAfter", "", time.Hour*24*365, "Duration for certificate validity")
	generateClientCMD.Flags().StringVarP(&clientCN, "CN", "", clientTemplate.Subject.CommonName, "Subject.CommonName")
	generateClientCMD.Flags().StringSliceVarP(&clientOrg, "Org", "", clientTemplate.Subject.Organization, "Subject.Organization")
	generateClientCMD.Flags().StringSliceVarP(&clientOU, "OU", "", clientTemplate.Subject.OrganizationalUnit, "Subject.OU")
	generateClientCMD.Flags().StringVarP(&clientCertName, "name", "n", "", "name for server certificate")
	generateClientCMD.MarkFlagRequired("name")
	generateCMD.AddCommand(generateClientCMD)
	rootCmd.AddCommand(generateCMD)

	logrus.SetReportCaller(false)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
}
func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

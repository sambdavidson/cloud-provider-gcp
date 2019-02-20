package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"k8s.io/client-go/util/cert"
	"k8s.io/klog"
)

const (
	certFileName         = "kubelet-client.crt"
	sealedKeyFileName    = "kubelet-client.key.sealed"
	tmpSealedKeyFileName = "kubelet-client.key.sealed.tmp"

	// PEM encoded type for the private and public bits of a sealed key.
	pemSealedPrivateType = "SEALED PRIVATE"
	pemSealedPublicType  = "SEALED PUBLIC"

	// Minimum age of existing certificate before triggering rotation.
	// Assuming no rotation errors, this is cert rotation period.
	rotationThreshold = 10 * 24 * time.Hour // 10 days
	// Caching duration for caller - will exec this plugin after this period.
	responseExpiry = time.Hour
	// validityLeeway is applied to NotBefore field of existing cert to account
	// for clock skew.
	validityLeeway = 5 * time.Minute
)

type requestCertFn func(tpmDevice, []byte) ([]byte, error)

type cache struct {
	directory   string
	requestCert requestCertFn
	tpm         tpmDevice
}

func (c *cache) keyCert() ([]byte, []byte, error) {
	tpm, err := openTPM(*tpmPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed opening TPM device: %v", err)
	}
	defer tpm.close()

	oldKey, oldCert, ok := c.existingKeyCert()
	if ok {
		klog.Info("re-using cached key and certificate")
		return oldKey, oldCert, nil
	}

	newKey, newCert, err := c.newKeyCert()
	if err != nil {
		if len(oldKey) == 0 || len(oldCert) == 0 {
			return nil, nil, err
		}
		klog.Errorf("failed rotating client certificate: %v", err)
		klog.Info("using existing key/cert that are still valid")
		return oldKey, oldCert, nil
	}
	return newKey, newCert, nil
}

func (c *cache) existingKeyCert() ([]byte, []byte, bool) {
	keyPEM, err := c.readSealedKey(sealedKeyFileName)
	if err != nil {
		klog.Errorf("failed reading existing private key: %v", err)
		return nil, nil, false
	}
	certPEM, err := c.readCert()
	if err != nil {
		klog.Errorf("failed reading existing certificate: %v", err)
		return nil, nil, false
	}
	// Check cert expiration.
	certRaw, _ := pem.Decode(certPEM)
	if certRaw == nil {
		klog.Error("failed parsing existing cert")
		return nil, nil, false
	}
	parsedCert, err := x509.ParseCertificate(certRaw.Bytes)
	if err != nil {
		klog.Errorf("failed parsing existing cert: %v", err)
		return nil, nil, false
	}
	if !validPEMKey(keyPEM, parsedCert) {
		klog.Error("existing private key is invalid or doesn't match existing certificate")
		return nil, nil, false
	}
	age := time.Now().Sub(parsedCert.NotBefore)
	remaining := parsedCert.NotAfter.Sub(time.Now())
	// Note: case order matters. Always check outside of expiry bounds first
	// and put cases that return non-nil key/cert at the bottom.
	switch {
	case remaining < responseExpiry:
		klog.Infof("existing cert expired or will expire in <%v, requesting new one", responseExpiry)
		return nil, nil, false
	case age+validityLeeway < 0:
		klog.Warningf("existing cert not valid yet, requesting new one")
		return nil, nil, false
	case age < rotationThreshold:
		return keyPEM, certPEM, true
	default:
		// Existing key/cert can still be reused but try to rotate.
		klog.Infof("existing cert is %v old, requesting new one", age)
		return keyPEM, certPEM, false
	}
}

func (c *cache) newKeyCert() ([]byte, []byte, error) {
	keyPEM, err := c.tempKeyPEM()
	if err != nil {
		return nil, nil, fmt.Errorf("trying to get private key: %v", err)
	}
	if err = c.sealAndWriteTmpKey(keyPEM); err != nil {
		return nil, nil, fmt.Errorf("writing temporary key PEM: %v", err)
	}

	klog.Info("requesting new certificate")
	certPEM, err := c.requestCert(c.tpm, keyPEM)
	if err != nil {
		return nil, nil, err
	}
	klog.Info("CSR approved, received certificate")

	if err = c.writeCert(certPEM); err != nil {
		return nil, nil, err
	}
	if err := os.Rename(filepath.Join(c.directory, tmpSealedKeyFileName), filepath.Join(c.directory, sealedKeyFileName)); err != nil {
		return nil, nil, err
	}
	return keyPEM, certPEM, nil
}

func (c *cache) tempKeyPEM() ([]byte, error) {
	keyPEM, err := c.readSealedKey(tmpSealedKeyFileName)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("trying to read temp private key: %v", err)
	}
	if err == nil && validPEMKey(keyPEM, nil) {
		return keyPEM, nil
	}

	// Either temp key doesn't exist or it's invalid.
	klog.Info("generating new private key")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: cert.ECPrivateKeyBlockType, Bytes: keyBytes})
	return keyPEM, nil
}

func (c *cache) readCert() ([]byte, error) {
	return ioutil.ReadFile(filepath.Join(c.directory, certFileName))
}
func (c *cache) writeCert(certPEM []byte) error {
	return ioutil.WriteFile(filepath.Join(c.directory, certFileName), certPEM, os.FileMode(0644))
}

// readSealedKey reads the sealed key with keyName and returns the
// unsealed key []byte.
func (c *cache) readSealedKey(keyName string) ([]byte, error) {
	sealedKeyPEM, err := ioutil.ReadFile(filepath.Join(c.directory, keyName))
	if err != nil {
		return nil, fmt.Errorf("reading sealed key PEM: %v", err)
	}
	privateBytes, publicBytes, err := pemDecodeSealedData(sealedKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("PEM decoding sealed key PEM parts: %v", err)
	}
	return c.tpm.unseal(privateBytes, publicBytes)
}

// sealAndWriteKey seals []byte key and writes the sealed key to the cache's
// directory.
func (c *cache) sealAndWriteTmpKey(keyPEM []byte) error {
	// Write private key into temporary file to reuse in case of failure.
	privateBytes, publicBytes, err := c.tpm.seal(keyPEM)
	if err != nil {
		return fmt.Errorf("sealing temporary key PEM: %v", err)
	}
	sealedKeyPEM, err := pemEncodeSealedData(privateBytes, publicBytes)
	if err != nil {
		return fmt.Errorf("PEM encoding sealed key PEM parts: %v", err)
	}

	return ioutil.WriteFile(filepath.Join(c.directory, tmpSealedKeyFileName), keyPEM, 0600)
}

// validPEMKey returns true if key contains a valid PEM-encoded private key. If
// cert is non-nil, it checks that key matches cert.
func validPEMKey(key []byte, cert *x509.Certificate) bool {
	if len(key) == 0 {
		return false
	}
	keyBlock, _ := pem.Decode(key)
	if keyBlock == nil {
		return false
	}
	pk, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return false
	}
	if cert == nil {
		return true
	}
	return reflect.DeepEqual(cert.PublicKey, pk.Public())
}

func pemEncodeSealedData(private, public []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{
		Type:  pemSealedPrivateType,
		Bytes: private,
	}); err != nil {
		return nil, err
	}
	if err := pem.Encode(buf, &pem.Block{
		Type:  pemSealedPublicType,
		Bytes: public,
	}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func pemDecodeSealedData(enc []byte) ([]byte, []byte, error) {
	privateBlock, rest := pem.Decode(enc)
	if privateBlock == nil || privateBlock.Type != pemSealedPrivateType {
		return nil, nil, fmt.Errorf("first decoded PEM block is not type %s: %s", pemSealedPrivateType, enc)
	}
	publicBlock, _ := pem.Decode(rest)
	if publicBlock == nil || publicBlock.Type != pemSealedPublicType {
		return nil, nil, fmt.Errorf("second decoded PEM block is not type %s: %s", pemSealedPublicType, rest)
	}
	return privateBlock.Bytes, publicBlock.Bytes, nil
}

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"reflect"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"k8s.io/cloud-provider-gcp/pkg/nodeidentity"
	"k8s.io/cloud-provider-gcp/pkg/tpmattest"
	"k8s.io/klog"
)

const (
	// Documented constant NVRAM addresses for AIK template and certificate
	// inside the TPM.
	aikCertIndex       = 0x01c10000
	aikTemplateIndex   = 0x01c10001
	sealedDataPassword = "sealedDataPassword"
)

var (
	srkPassword = "srkPassword"
	srkTemplate = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagNoDA,
		AuthPolicy: nil,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			Exponent:   0,
			ModulusRaw: make([]byte, 256),
		},
	}
)

// TPM 2.0 specification can be found at
// https://trustedcomputinggroup.org/resource/tpm-library-specification/
//
// Most relevant are "Part 1: Architecture" and  "Part 3: Commands".

type tpmDevice interface {
	createPrimaryRawTemplate([]byte) (tpmutil.Handle, crypto.PublicKey, error)
	certify(tpmutil.Handle, tpmutil.Handle) ([]byte, []byte, error)
	nvRead(tpmutil.Handle) ([]byte, error)
	loadExternal(tpm2.Public, tpm2.Private) (tpmutil.Handle, error)
	seal([]byte) ([]byte, []byte, error)
	unseal(privateBlob []byte, publicBlob []byte) ([]byte, error)
	flush(tpmutil.Handle)
	close() error
}

type realTPM struct {
	rwc io.ReadWriteCloser
}

func openTPM(path string) (*realTPM, error) {
	rw, err := tpm2.OpenTPM(path)
	if err != nil {
		return nil, fmt.Errorf("tpm2.OpenTPM(%q): %v", path, err)
	}
	return &realTPM{rw}, nil
}

func (t *realTPM) createPrimaryRawTemplate(pub []byte) (tpmutil.Handle, crypto.PublicKey, error) {
	return tpm2.CreatePrimaryRawTemplate(t.rwc, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", pub)
}
func (t *realTPM) certify(kh, aikh tpmutil.Handle) ([]byte, []byte, error) {
	return tpm2.Certify(t.rwc, "", "", kh, aikh, nil)
}
func (t *realTPM) nvRead(h tpmutil.Handle) ([]byte, error) {
	return tpm2.NVRead(t.rwc, h)
}
func (t *realTPM) loadExternal(pub tpm2.Public, priv tpm2.Private) (tpmutil.Handle, error) {
	kh, _, err := tpm2.LoadExternal(t.rwc, pub, priv, tpm2.HandleNull)
	return kh, err
}
func (t *realTPM) seal(sensitiveData []byte) (privateArea []byte, publicArea []byte, retErr error) {
	srkHandle, _, err := tpm2.CreatePrimary(t.rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", srkPassword, srkTemplate)
	if err != nil {
		return nil, nil, fmt.Errorf("can't create primary key: %v", err)
	}
	defer func() {
		if err := tpm2.FlushContext(t.rwc, srkHandle); err != nil {
			retErr = fmt.Errorf("%v\nunable to flush SRK handle %q: %v", retErr, srkHandle, err)
		}
	}()

	sessHandle, policy, err := policyPCRPasswordSession(t.rwc, *pcr, sealedDataPassword)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get policy: %v", err)
	}
	defer func() {
		if err := tpm2.FlushContext(t.rwc, sessHandle); err != nil {
			retErr = fmt.Errorf("%v\nunable to flush session: %v", retErr, err)
		}
	}()

	return tpm2.Seal(t.rwc, srkHandle, srkPassword, sealedDataPassword, policy, sensitiveData)
}
func (t *realTPM) unseal(privateBlob []byte, publicBlob []byte) (data []byte, retErr error) {
	// Create a storage root key
	srkHandle, _, err := tpm2.CreatePrimary(t.rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", srkPassword, srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("can't create primary key: %v", err)
	}
	defer func() {
		if err := tpm2.FlushContext(t.rwc, srkHandle); err != nil {
			retErr = fmt.Errorf("%v\nunable to flush SRK handle %q: %v", retErr, srkHandle, err)
		}
	}()

	// Create the authorization session
	sessHandle, _, err := policyPCRPasswordSession(t.rwc, *pcr, sealedDataPassword)
	if err != nil {
		return nil, fmt.Errorf("unable to get auth session: %v", err)
	}
	defer func() {
		if err := tpm2.FlushContext(t.rwc, sessHandle); err != nil {
			retErr = fmt.Errorf("%v\nunable to flush session: %v", retErr, err)
		}
	}()

	// Load the sealed data into the TPM.
	sealedDataHandle, _, err := tpm2.Load(t.rwc, srkHandle, srkPassword, publicBlob, privateBlob)
	if err != nil {
		return nil, fmt.Errorf("unable to load data: %v", err)
	}
	defer func() {
		if err := tpm2.FlushContext(t.rwc, sealedDataHandle); err != nil {
			retErr = fmt.Errorf("%v\nunable to flush object handle %q: %v", retErr, sealedDataHandle, err)
		}
	}()

	return tpm2.UnsealWithSession(t.rwc, sessHandle, sealedDataHandle, sealedDataPassword)
}
func (t *realTPM) flush(h tpmutil.Handle) {
	if err := tpm2.FlushContext(t.rwc, h); err != nil {
		klog.Errorf("tpm2.Flush(0x%x): %v", h, err)
	}
}
func (t *realTPM) close() error { return t.rwc.Close() }

// We don't have GCE metadata during tests, allow override.
var newNodeIdentity = nodeidentity.FromMetadata

// tpmAttest generates an attestation signature for privateKey using AIK in
// TPM. Returned bytes are concatenated PEM blocks of the signature,
// attestation data and AIK certificate.
//
// High-level flow (TPM commands in parens):
// - load AIK from template in NVRAM (TPM2_NV_ReadPublic, TPM2_NV_Read,
//   TPM2_CreatePrimary)
// - load privateKey into the TPM (TPM2_LoadExternal)
// - certify (sign) privateKey with AIK (TPM2_Certify)
// - read AIK certificate from NVRAM (TPM2_NV_ReadPubluc, TPM2_NV_Read)
func tpmAttest(dev tpmDevice, privateKey crypto.PrivateKey) ([]byte, error) {
	aikh, aikPub, err := loadPrimaryKey(dev)
	if err != nil {
		return nil, fmt.Errorf("loadPrimaryKey: %v", err)
	}
	defer dev.flush(aikh)
	klog.Info("loaded AIK")

	kh, err := loadTLSKey(dev, privateKey)
	if err != nil {
		return nil, fmt.Errorf("loadTLSKey: %v", err)
	}
	defer dev.flush(kh)
	klog.Info("loaded TLS key")

	attest, sig, err := dev.certify(kh, aikh)
	if err != nil {
		return nil, fmt.Errorf("certify failed: %v", err)
	}
	klog.Info("TLS key certified by AIK")

	// Sanity-check the signature.
	attestHash := sha256.Sum256(attest)
	if err := rsa.VerifyPKCS1v15(aikPub.(*rsa.PublicKey), crypto.SHA256, attestHash[:], sig); err != nil {
		return nil, fmt.Errorf("Signature verification failed: %v", err)
	}
	klog.Info("certification signature verified with AIK public key")

	// Try loading AIK cert, but don't fail if it wasn't provisioned.
	//
	// TODO(awly): make missing AIK cert an error eventually provisioning is
	// reliable enough.
	aikCertRaw, aikCert, err := readAIKCert(dev, aikh, aikPub)
	if err != nil {
		klog.Errorf("failed reading AIK cert: %v", err)
		klog.Info("proceeding without AIK cert in CSR")
	} else {
		klog.Info("AIK cert loaded")

		// Sanity-check that AIK cert matches AIK.
		aikCertPub := aikCert.PublicKey.(*rsa.PublicKey)
		if !reflect.DeepEqual(aikPub, aikCertPub) {
			return nil, fmt.Errorf("AIK public key doesn't match certificate public key")
		}
		if err := rsa.VerifyPKCS1v15(aikCertPub, crypto.SHA256, attestHash[:], sig); err != nil {
			return nil, fmt.Errorf("verifying certification signature with AIK cert: %v", err)
		}
	}

	id, err := newNodeIdentity()
	if err != nil {
		return nil, fmt.Errorf("fetching VM identity from GCE metadata: %v", err)
	}
	idRaw, err := json.Marshal(id)
	if err != nil {
		return nil, fmt.Errorf("marshaling VM identity: %v", err)
	}

	buf := new(bytes.Buffer)
	// OK to ignore errors from pem.Encode below because buf.Write never fails.
	pem.Encode(buf, &pem.Block{
		Type:  "ATTESTATION DATA",
		Bytes: attest,
	})
	pem.Encode(buf, &pem.Block{
		Type:  "ATTESTATION SIGNATURE",
		Bytes: sig,
	})
	pem.Encode(buf, &pem.Block{
		Type:  "VM IDENTITY",
		Bytes: idRaw,
	})
	if len(aikCertRaw) > 0 {
		pem.Encode(buf, &pem.Block{
			Type:  "ATTESTATION CERTIFICATE",
			Bytes: aikCertRaw,
		})
	}
	return buf.Bytes(), nil
}

func loadPrimaryKey(dev tpmDevice) (tpmutil.Handle, crypto.PublicKey, error) {
	aikTemplate, err := dev.nvRead(aikTemplateIndex)
	if err != nil {
		return 0, nil, fmt.Errorf("tpm2.NVRead(AIK template): %v", err)
	}
	aikh, aikPub, err := dev.createPrimaryRawTemplate(aikTemplate)
	if err != nil {
		return 0, nil, fmt.Errorf("tpm2.CreatePrimary: %v", err)
	}
	return aikh, aikPub, nil
}

func readAIKCert(dev tpmDevice, aikh tpmutil.Handle, aikPub crypto.PublicKey) ([]byte, *x509.Certificate, error) {
	aikCert, err := dev.nvRead(tpmutil.Handle(aikCertIndex))
	if err != nil {
		return nil, nil, fmt.Errorf("tpm2.NVRead(AIK cert): %v", err)
	}

	crt, err := x509.ParseCertificate(aikCert)
	if err != nil {
		return aikCert, nil, fmt.Errorf("parsing AIK cert: %v", err)
	}
	return aikCert, crt, nil
}

func loadTLSKey(dev tpmDevice, privateKey crypto.PrivateKey) (tpmutil.Handle, error) {
	pk, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return 0, fmt.Errorf("only EC keys are supported, got %T", privateKey)
	}
	pub, err := tpmattest.MakePublic(pk.Public())
	if err != nil {
		return 0, fmt.Errorf("failed to build TPMT_PUBLIC struct: %v", err)
	}
	private := tpm2.Private{
		Type:      tpm2.AlgECC,
		Sensitive: pk.D.Bytes(),
	}
	kh, err := dev.loadExternal(pub, private)
	if err != nil {
		return 0, fmt.Errorf("loadExternal: %v", err)
	}
	return kh, nil
}

func policyPCRPasswordSession(rwc io.ReadWriteCloser, pcr int, password string) (sessHandle tpmutil.Handle, policy []byte, retErr error) {
	// This is not a very secure session but since this TPM access is single-op
	// and local it is not a big deal.
	sessHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return tpm2.HandleNull, nil, fmt.Errorf("unable to start session: %v", err)
	}
	defer func() {
		if sessHandle != tpm2.HandleNull && err != nil {
			if err := tpm2.FlushContext(rwc, sessHandle); err != nil {
				retErr = fmt.Errorf("%v\nunable to flush session: %v", retErr, err)
			}
		}
	}()

	pcrSelection := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{pcr},
	}

	// An empty expected digest means that digest verification is skipped.
	if err := tpm2.PolicyPCR(rwc, sessHandle, nil /*expectedDigest*/, pcrSelection); err != nil {
		return sessHandle, nil, fmt.Errorf("unable to bind PCRs to auth policy: %v", err)
	}

	if err := tpm2.PolicyPassword(rwc, sessHandle); err != nil {
		return sessHandle, nil, fmt.Errorf("unable to require password for auth policy: %v", err)
	}

	policy, err = tpm2.PolicyGetDigest(rwc, sessHandle)
	if err != nil {
		return sessHandle, nil, fmt.Errorf("unable to get policy digest: %v", err)
	}
	return sessHandle, policy, nil
}

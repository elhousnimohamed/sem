package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

func main() {
	// Generate certificate that will expire in 2 minutes
	certBytes, privateKeyBytes, err := generateSelfSignedCert(2 * time.Minute)
	if err != nil {
		fmt.Printf("Error generating certificate: %v\n", err)
		os.Exit(1)
	}

	// Save the certificate and private key to files for inspection
	err = os.WriteFile("temp-cert.pem", certBytes, 0644)
	if err != nil {
		fmt.Printf("Error saving certificate: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile("temp-key.pem", privateKeyBytes, 0644)
	if err != nil {
		fmt.Printf("Error saving private key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Certificate and private key generated and saved to temp files")

	// Upload to AWS IAM
	certName := fmt.Sprintf("short-lived-cert-%d", time.Now().Unix())
	err = uploadCertToIAM(certName, certBytes, privateKeyBytes)
	if err != nil {
		fmt.Printf("Error uploading certificate to IAM: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Certificate successfully uploaded to IAM with name: %s\n", certName)
	fmt.Printf("Certificate will expire in 2 minutes\n")
}

// generateSelfSignedCert creates a self-signed certificate with the specified expiration duration
func generateSelfSignedCert(expiration time.Duration) ([]byte, []byte, error) {
	// Create private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Prepare certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(expiration)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Temporary Certificate Co"},
			CommonName:   "temporary-cert.example.com",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	// Encode private key to PEM
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, privKeyPEM, nil
}

// uploadCertToIAM uploads the certificate to AWS IAM
func uploadCertToIAM(certName string, certPEM, privateKeyPEM []byte) error {
	// Create AWS session
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return fmt.Errorf("failed to create AWS session: %w", err)
	}

	// Create IAM service client
	svc := iam.New(sess)

	// Upload server certificate
	input := &iam.UploadServerCertificateInput{
		CertificateBody:       aws.String(string(certPEM)),
		PrivateKey:            aws.String(string(privateKeyPEM)),
		ServerCertificateName: aws.String(certName),
		// If you need a certificate chain, you would include it here:
		// CertificateChain:      aws.String(string(chainPEM)),
	}

	_, err = svc.UploadServerCertificate(input)
	if err != nil {
		return fmt.Errorf("failed to upload certificate: %w", err)
	}

	return nil
}

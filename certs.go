package certificatemanagement

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// SSLCertificateInfo represents details of an SSL certificate
type SSLCertificateInfo struct {
	ARN          string
	Name         string
	Path         string
	UploadDate   time.Time
	ExpirationDate time.Time
}

// CheckAndDeleteExpiredSSLCertificate checks if an SSL certificate is expired and deletes it if necessary
func CheckAndDeleteExpiredSSLCertificate(certificateARN string) (*SSLCertificateInfo, error) {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %v", err)
	}

	// Create IAM client
	iamClient := iam.NewFromConfig(cfg)

	// Get SSL certificate metadata
	certInput := &iam.GetServerCertificateInput{
		ServerCertificateName: aws.String(extractCertificateName(certificateARN)),
	}
	
	certOutput, err := iamClient.GetServerCertificate(context.TODO(), certInput)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve SSL certificate: %v", err)
	}

	// Extract certificate details
	certInfo := &SSLCertificateInfo{
		ARN:  certificateARN,
		Name: *certOutput.ServerCertificate.ServerCertificateMetadata.ServerCertificateName,
		Path: *certOutput.ServerCertificate.ServerCertificateMetadata.Path,
		UploadDate: *certOutput.ServerCertificate.ServerCertificateMetadata.UploadDate,
	}

	// Parse the X.509 certificate to get expiration date
	cert, err := parseCertificate(certOutput.ServerCertificate.CertificateBody)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	certInfo.ExpirationDate = cert.NotAfter

	// Check if certificate is expired
	if time.Now().After(certInfo.ExpirationDate) {
		// Delete expired certificate
		deleteInput := &iam.DeleteServerCertificateInput{
			ServerCertificateName: &certInfo.Name,
		}

		_, err = iamClient.DeleteServerCertificate(context.TODO(), deleteInput)
		if err != nil {
			return certInfo, fmt.Errorf("failed to delete expired certificate: %v", err)
		}

		return certInfo, fmt.Errorf("certificate %s has been deleted due to expiration", certInfo.Name)
	}

	// Calculate days until expiration
	daysUntilExpiration := int(time.Until(certInfo.ExpirationDate).Hours() / 24)

	// Log or handle certificates close to expiration
	if daysUntilExpiration <= 30 {
		fmt.Printf("Warning: Certificate %s will expire in %d days\n", certInfo.Name, daysUntilExpiration)
	}

	return certInfo, nil
}

// extractCertificateName extracts the certificate name from the ARN
func extractCertificateName(arn string) string {
	// Implement ARN parsing logic
	// Typical ARN format: arn:aws:iam::ACCOUNT-ID:server-certificate/CERTIFICATE-NAME
	// This is a placeholder implementation
	// You might want to use a more robust ARN parsing method
	parts := strings.Split(arn, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return arn
}

// parseCertificate parses the X.509 certificate to extract expiration date
func parseCertificate(certBody string) (*x509.Certificate, error) {
	// Parse PEM encoded certificate
	block, _ := pem.Decode([]byte(certBody))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	// Parse X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %v", err)
	}

	return cert, nil
}

// Example usage function
func ExampleSSLCertificateManagement() {
	// Example SSL Certificate ARN
	certificateARN := "arn:aws:iam::123456789012:server-certificate/example-cert"

	// Check and potentially delete expired certificate
	certInfo, err := CheckAndDeleteExpiredSSLCertificate(certificateARN)
	if err != nil {
		fmt.Printf("Error processing certificate: %v\n", err)
		return
	}

	// Print certificate details if not expired
	fmt.Printf("Certificate Details:\n")
	fmt.Printf("Name: %s\n", certInfo.Name)
	fmt.Printf("Uploaded: %s\n", certInfo.UploadDate)
	fmt.Printf("Expires: %s\n", certInfo.ExpirationDate)
}

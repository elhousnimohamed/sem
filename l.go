package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func main() {
	// Parse command line arguments
	certificateIdentifier := flag.String("certificate", "", "Certificate name or ARN")
	flag.Parse()

	if *certificateIdentifier == "" {
		log.Fatal("Certificate identifier must be provided using --certificate flag")
	}

	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("Failed to load AWS configuration: %v", err)
	}

	// Create IAM client
	client := iam.NewFromConfig(cfg)

	// Check if certificate exists
	exists, err := certificateExists(context.TODO(), client, *certificateIdentifier)
	if err != nil {
		log.Fatalf("Error checking certificate existence: %v", err)
	}

	if exists {
		log.Printf("Certificate '%s' exists", *certificateIdentifier)
		os.Exit(0)
	} else {
		log.Printf("Certificate '%s' does not exist", *certificateIdentifier)
		os.Exit(1)
	}
}

func certificateExists(ctx context.Context, client *iam.Client, identifier string) (bool, error) {
	paginator := iam.NewListServerCertificatesPaginator(client, &iam.ListServerCertificatesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return false, err
		}

		for _, cert := range page.ServerCertificateMetadataList {
			if aws.ToString(cert.ServerCertificateName) == identifier {
				return true, nil
			}
			if aws.ToString(cert.Arn) == identifier {
				return true, nil
			}
		}
	}

	return false, nil
}

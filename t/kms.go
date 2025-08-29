package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	DefaultRotationPeriodDays = 365
)

type KMSRotationManager struct {
	client *kms.Client
}

func NewKMSRotationManager(ctx context.Context) (*KMSRotationManager, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &KMSRotationManager{
		client: kms.NewFromConfig(cfg),
	}, nil
}

func (k *KMSRotationManager) GetKeyRotationStatus(ctx context.Context, keyArn string) (*kms.GetKeyRotationStatusOutput, error) {
	input := &kms.GetKeyRotationStatusInput{
		KeyId: aws.String(keyArn),
	}

	result, err := k.client.GetKeyRotationStatus(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get key rotation status: %w", err)
	}

	return result, nil
}

func (k *KMSRotationManager) ValidateKey(ctx context.Context, keyArn string) error {
	input := &kms.DescribeKeyInput{
		KeyId: aws.String(keyArn),
	}

	result, err := k.client.DescribeKey(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to describe key: %w", err)
	}

	// Check if it's a customer-managed key
	if result.KeyMetadata.Origin != types.OriginTypeAwsKms {
		return fmt.Errorf("key is not a customer-managed key (origin: %s)", result.KeyMetadata.Origin)
	}

	// Check if it's a symmetric key
	if result.KeyMetadata.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
		return fmt.Errorf("key is not a symmetric encryption key (usage: %s)", result.KeyMetadata.KeyUsage)
	}

	// Check key state
	if result.KeyMetadata.KeyState != types.KeyStateEnabled {
		return fmt.Errorf("key is not enabled (state: %s)", result.KeyMetadata.KeyState)
	}

	return nil
}

func (k *KMSRotationManager) EnableKeyRotation(ctx context.Context, keyArn string, rotationPeriodDays int) error {
	input := &kms.EnableKeyRotationInput{
		KeyId:                aws.String(keyArn),
		RotationPeriodInDays: aws.Int32(int32(rotationPeriodDays)),
	}

	_, err := k.client.EnableKeyRotation(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to enable key rotation: %w", err)
	}

	return nil
}

func (k *KMSRotationManager) ProcessKey(ctx context.Context, keyArn string, rotationPeriodDays int) error {
	fmt.Printf("Processing KMS key: %s\n", keyArn)

	// Validate the key
	if err := k.ValidateKey(ctx, keyArn); err != nil {
		return fmt.Errorf("key validation failed: %w", err)
	}
	fmt.Println("✓ Key validation passed")

	// Check current rotation status
	rotationStatus, err := k.GetKeyRotationStatus(ctx, keyArn)
	if err != nil {
		return fmt.Errorf("failed to check rotation status: %w", err)
	}

	if rotationStatus.KeyRotationEnabled {
		fmt.Printf("✓ Key rotation is already enabled\n")
		if rotationStatus.RotationPeriodInDays != nil {
			fmt.Printf("  Current rotation period: %d days\n", *rotationStatus.RotationPeriodInDays)
		}
		
		// Check if we need to update the rotation period
		if rotationStatus.RotationPeriodInDays == nil || 
		   int(*rotationStatus.RotationPeriodInDays) != rotationPeriodDays {
			fmt.Printf("  Updating rotation period to %d days...\n", rotationPeriodDays)
			if err := k.EnableKeyRotation(ctx, keyArn, rotationPeriodDays); err != nil {
				return fmt.Errorf("failed to update rotation period: %w", err)
			}
			fmt.Println("✓ Rotation period updated successfully")
		}
		return nil
	}

	// Enable key rotation
	fmt.Printf("⚠ Key rotation is disabled. Enabling with %d day period...\n", rotationPeriodDays)
	if err := k.EnableKeyRotation(ctx, keyArn, rotationPeriodDays); err != nil {
		return fmt.Errorf("failed to enable key rotation: %w", err)
	}

	fmt.Println("✓ Key rotation enabled successfully")
	return nil
}

func main() {
	var (
		keyArn        = flag.String("key-arn", "", "KMS key ARN (required)")
		rotationDays  = flag.String("rotation-days", "", "Rotation period in days (default: 365)")
		help          = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	if *help {
		fmt.Println("KMS Key Rotation Manager")
		fmt.Println("Usage:")
		fmt.Printf("  %s -key-arn <ARN> [-rotation-days <DAYS>]\n", os.Args[0])
		fmt.Println("\nFlags:")
		flag.PrintDefaults()
		fmt.Println("\nExample:")
		fmt.Printf("  %s -key-arn arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012 -rotation-days 180\n", os.Args[0])
		return
	}

	if *keyArn == "" {
		log.Fatal("Error: -key-arn flag is required")
	}

	// Parse rotation period
	rotationPeriodDays := DefaultRotationPeriodDays
	if *rotationDays != "" {
		period, err := strconv.Atoi(*rotationDays)
		if err != nil {
			log.Fatalf("Error: invalid rotation-days value '%s': %v", *rotationDays, err)
		}
		if period < 90 || period > 2560 {
			log.Fatal("Error: rotation period must be between 90 and 2560 days")
		}
		rotationPeriodDays = period
	}

	ctx := context.Background()

	// Initialize KMS manager
	manager, err := NewKMSRotationManager(ctx)
	if err != nil {
		log.Fatalf("Error: failed to initialize KMS manager: %v", err)
	}

	// Process the key
	if err := manager.ProcessKey(ctx, *keyArn, rotationPeriodDays); err != nil {
		log.Fatalf("Error: %v", err)
	}

	fmt.Println("\n🎉 Operation completed successfully!")
}

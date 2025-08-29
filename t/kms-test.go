package main

import (
	"context"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// TestKMSRotationManager contains integration tests for the KMS rotation functionality
type TestKMSRotationManager struct {
	client    *kms.Client
	testKeyId *string
	ctx       context.Context
}

// NewTestKMSRotationManager creates a new test manager
func NewTestKMSRotationManager(t *testing.T) *TestKMSRotationManager {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	return &TestKMSRotationManager{
		client: kms.NewFromConfig(cfg),
		ctx:    ctx,
	}
}

// CreateTestKey creates a customer-managed symmetric key for testing
func (tm *TestKMSRotationManager) CreateTestKey(t *testing.T) string {
	keyPolicy := `{
		"Version": "2012-10-17",
		"Id": "key-policy-1",
		"Statement": [
			{
				"Sid": "Enable IAM User Permissions",
				"Effect": "Allow",
				"Principal": {
					"AWS": "arn:aws:iam::*:root"
				},
				"Action": "kms:*",
				"Resource": "*"
			}
		]
	}`

	input := &kms.CreateKeyInput{
		Description: aws.String("Test key for rotation integration test"),
		KeyUsage:    types.KeyUsageTypeEncryptDecrypt,
		KeySpec:     types.KeySpecSymmetricDefault,
		Origin:      types.OriginTypeAwsKms,
		Policy:      aws.String(keyPolicy),
		Tags: []types.Tag{
			{
				TagKey:   aws.String("Purpose"),
				TagValue: aws.String("IntegrationTest"),
			},
			{
				TagKey:   aws.String("CreatedBy"),
				TagValue: aws.String("KMSRotationTest"),
			},
		},
	}

	result, err := tm.client.CreateKey(tm.ctx, input)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	tm.testKeyId = result.KeyMetadata.KeyId
	keyArn := *result.KeyMetadata.Arn

	t.Logf("✓ Created test KMS key: %s", keyArn)
	t.Logf("  Key ID: %s", *tm.testKeyId)
	
	return keyArn
}

// CleanupTestKey deletes the test key
func (tm *TestKMSRotationManager) CleanupTestKey(t *testing.T) {
	if tm.testKeyId == nil {
		return
	}

	// Schedule key deletion (minimum 7 days)
	input := &kms.ScheduleKeyDeletionInput{
		KeyId:               tm.testKeyId,
		PendingWindowInDays: aws.Int32(7), // Minimum allowed
	}

	result, err := tm.client.ScheduleKeyDeletion(tm.ctx, input)
	if err != nil {
		t.Errorf("Failed to schedule key deletion: %v", err)
		return
	}

	t.Logf("✓ Scheduled test key deletion on: %v", result.DeletionDate)
}

// CheckInitialRotationStatus verifies the key starts with rotation disabled
func (tm *TestKMSRotationManager) CheckInitialRotationStatus(t *testing.T, keyArn string) {
	input := &kms.GetKeyRotationStatusInput{
		KeyId: aws.String(keyArn),
	}

	result, err := tm.client.GetKeyRotationStatus(tm.ctx, input)
	if err != nil {
		t.Fatalf("Failed to get initial rotation status: %v", err)
	}

	if result.KeyRotationEnabled {
		t.Fatal("Expected key rotation to be disabled initially, but it was enabled")
	}

	t.Log("✓ Confirmed key rotation is initially disabled")
}

// TestRotationScript tests the main rotation functionality
func (tm *TestKMSRotationManager) TestRotationScript(t *testing.T, keyArn string, rotationDays int) {
	manager, err := NewKMSRotationManager(tm.ctx)
	if err != nil {
		t.Fatalf("Failed to create rotation manager: %v", err)
	}

	err = manager.ProcessKey(tm.ctx, keyArn, rotationDays)
	if err != nil {
		t.Fatalf("Failed to process key rotation: %v", err)
	}

	t.Log("✓ Key rotation processing completed successfully")
}

// VerifyRotationEnabled checks that rotation was properly enabled
func (tm *TestKMSRotationManager) VerifyRotationEnabled(t *testing.T, keyArn string, expectedDays int) {
	input := &kms.GetKeyRotationStatusInput{
		KeyId: aws.String(keyArn),
	}

	result, err := tm.client.GetKeyRotationStatus(tm.ctx, input)
	if err != nil {
		t.Fatalf("Failed to verify rotation status: %v", err)
	}

	if !result.KeyRotationEnabled {
		t.Fatal("Expected key rotation to be enabled, but it was disabled")
	}

	if result.RotationPeriodInDays == nil {
		t.Fatal("Expected rotation period to be set, but it was nil")
	}

	actualDays := int(*result.RotationPeriodInDays)
	if actualDays != expectedDays {
		t.Fatalf("Expected rotation period to be %d days, but got %d days", expectedDays, actualDays)
	}

	t.Logf("✓ Verified key rotation is enabled with %d day period", actualDays)
}

// TestRotationIdempotency tests that running the script multiple times is safe
func (tm *TestKMSRotationManager) TestRotationIdempotency(t *testing.T, keyArn string, rotationDays int) {
	manager, err := NewKMSRotationManager(tm.ctx)
	if err != nil {
		t.Fatalf("Failed to create rotation manager: %v", err)
	}

	// Run the script a second time
	t.Log("Running rotation script a second time to test idempotency...")
	err = manager.ProcessKey(tm.ctx, keyArn, rotationDays)
	if err != nil {
		t.Fatalf("Failed on second run of key rotation: %v", err)
	}

	// Verify rotation is still enabled with correct period
	tm.VerifyRotationEnabled(t, keyArn, rotationDays)
	t.Log("✓ Script is idempotent - second run completed successfully")
}

// Integration test function
func TestKMSKeyRotationIntegration(t *testing.T) {
	testRotationDays := 180

	tm := NewTestKMSRotationManager(t)
	
	// Create test key
	keyArn := tm.CreateTestKey(t)
	
	// Ensure cleanup happens even if test fails
	defer tm.CleanupTestKey(t)

	// Wait a moment for key to be fully available
	time.Sleep(2 * time.Second)

	// Test sequence
	t.Run("CheckInitialState", func(t *testing.T) {
		tm.CheckInitialRotationStatus(t, keyArn)
	})

	t.Run("EnableRotation", func(t *testing.T) {
		tm.TestRotationScript(t, keyArn, testRotationDays)
	})

	t.Run("VerifyRotationEnabled", func(t *testing.T) {
		tm.VerifyRotationEnabled(t, keyArn, testRotationDays)
	})

	t.Run("TestIdempotency", func(t *testing.T) {
		tm.TestRotationIdempotency(t, keyArn, testRotationDays)
	})

	t.Log("🎉 All integration tests passed!")
}

// Test with default rotation period
func TestKMSKeyRotationDefault(t *testing.T) {
	tm := NewTestKMSRotationManager(t)
	
	// Create test key
	keyArn := tm.CreateTestKey(t)
	defer tm.CleanupTestKey(t)

	// Wait a moment for key to be fully available
	time.Sleep(2 * time.Second)

	// Test with default period
	tm.TestRotationScript(t, keyArn, DefaultRotationPeriodDays)
	tm.VerifyRotationEnabled(t, keyArn, DefaultRotationPeriodDays)

	t.Log("✓ Default rotation period test passed!")
}

// Benchmark test function that can be run manually
func BenchmarkKeyRotationOperation(b *testing.B) {
	tm := NewTestKMSRotationManager((*testing.T)(b))
	keyArn := tm.CreateTestKey((*testing.T)(b))
	defer tm.CleanupTestKey((*testing.T)(b))

	time.Sleep(2 * time.Second)

	manager, err := NewKMSRotationManager(tm.ctx)
	if err != nil {
		b.Fatalf("Failed to create rotation manager: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := manager.ProcessKey(tm.ctx, keyArn, 365)
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}

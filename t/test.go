package iammanagement

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// TestIAMUserConsoleAccess demonstrates a complete test scenario
func TestIAMUserConsoleAccess(t *testing.T) {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		t.Fatalf("Failed to load AWS configuration: %v", err)
	}

	// Create IAM client
	iamClient := iam.NewFromConfig(cfg)

	// Test username - use a real IAM username in your AWS account
	testUsername := "your-test-username"

	// Subtest 1: Check if user exists
	t.Run("UserExists", func(t *testing.T) {
		_, err := iamClient.GetUser(context.TODO(), &iam.GetUserInput{
			UserName: &testUsername,
		})
		if err != nil {
			t.Fatalf("User %s does not exist: %v", testUsername, err)
		}
	})

	// Subtest 2: Check Console Access
	t.Run("CheckConsoleAccess", func(t *testing.T) {
		hasAccess, err := CheckUserConsoleAccess(testUsername)
		if err != nil {
			t.Fatalf("Error checking console access: %v", err)
		}
		t.Logf("User %s console access: %v", testUsername, hasAccess)
	})

	// Subtest 3: Remove Console Access
	t.Run("RemoveConsoleAccess", func(t *testing.T) {
		err := RemoveUserConsoleAccess(testUsername)
		if err != nil {
			t.Fatalf("Failed to remove console access: %v", err)
		}

		// Verify access was removed
		hasAccess, err := CheckUserConsoleAccess(testUsername)
		if err != nil {
			t.Fatalf("Error re-checking console access: %v", err)
		}
		if hasAccess {
			t.Fatalf("Console access was not successfully removed")
		}
	})
}

// Helper function to create a test user with console access
func createTestUserWithConsoleAccess(t *testing.T) string {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		t.Fatalf("Failed to load AWS configuration: %v", err)
	}

	// Create IAM client
	iamClient := iam.NewFromConfig(cfg)

	// Generate a unique username
	testUsername := fmt.Sprintf("test-user-%d", time.Now().UnixNano())

	// Create IAM user
	_, err = iamClient.CreateUser(context.TODO(), &iam.CreateUserInput{
		UserName: &testUsername,
	})
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create login profile (console access)
	_, err = iamClient.CreateLoginProfile(context.TODO(), &iam.CreateLoginProfileInput{
		UserName: &testUsername,
		Password: aws.String("TestPassword123!"), // Use a strong, temporary password
		PasswordResetRequired: aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("Failed to create login profile: %v", err)
	}

	return testUsername
}

// Cleanup function to remove test user
func cleanupTestUser(t *testing.T, username string) {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		t.Fatalf("Failed to load AWS configuration: %v", err)
	}

	// Create IAM client
	iamClient := iam.NewFromConfig(cfg)

	// Delete login profile
	_, err = iamClient.DeleteLoginProfile(context.TODO(), &iam.DeleteLoginProfileInput{
		UserName: &username,
	})
	if err != nil {
		t.Logf("Failed to delete login profile: %v", err)
	}

	// Delete user
	_, err = iamClient.DeleteUser(context.TODO(), &iam.DeleteUserInput{
		UserName: &username,
	})
	if err != nil {
		t.Logf("Failed to delete test user: %v", err)
	}
}

// Integration test with full lifecycle
func TestIAMUserConsoleAccessLifecycle(t *testing.T) {
	// Create a test user with console access
	testUsername := createTestUserWithConsoleAccess(t)
	
	// Ensure cleanup happens at the end
	defer cleanupTestUser(t, testUsername)

	// Check initial console access
	hasAccess, err := CheckUserConsoleAccess(testUsername)
	if err != nil {
		t.Fatalf("Error checking initial console access: %v", err)
	}
	if !hasAccess {
		t.Fatalf("User should have console access initially")
	}

	// Remove console access
	err = RemoveUserConsoleAccess(testUsername)
	if err != nil {
		t.Fatalf("Failed to remove console access: %v", err)
	}

	// Verify access removed
	hasAccess, err = CheckUserConsoleAccess(testUsername)
	if err != nil {
		t.Fatalf("Error re-checking console access: %v", err)
	}
	if hasAccess {
		t.Fatalf("Console access was not successfully removed")
	}
}

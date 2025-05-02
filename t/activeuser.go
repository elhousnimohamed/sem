package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// HasTooManyActiveAccessKeys checks if an IAM user has more than 2 active access keys
func HasTooManyActiveAccessKeys(ctx context.Context, client *iam.Client, username string) (bool, int, error) {
	input := &iam.ListAccessKeysInput{
		UserName: aws.String(username),
	}

	result, err := client.ListAccessKeys(ctx, input)
	if err != nil {
		return false, 0, fmt.Errorf("error listing access keys for user %s: %v", username, err)
	}

	// Count active access keys
	activeCount := 0
	for _, key := range result.AccessKeyMetadata {
		if key.Status == types.StatusTypeActive {
			activeCount++
		}
	}

	// Check if there are more than 2 active access keys
	return activeCount > 2, activeCount, nil
}

// IsAccessKeyActiveAndExists checks if a specific access key exists and is active for a user
func IsAccessKeyActiveAndExists(ctx context.Context, client *iam.Client, username, accessKeyID string) (bool, error) {
	input := &iam.ListAccessKeysInput{
		UserName: aws.String(username),
	}

	result, err := client.ListAccessKeys(ctx, input)
	if err != nil {
		return false, fmt.Errorf("error listing access keys for user %s: %v", username, err)
	}

	// Check if the access key exists and is active
	for _, key := range result.AccessKeyMetadata {
		if aws.ToString(key.AccessKeyId) == accessKeyID {
			return key.Status == types.StatusTypeActive, nil
		}
	}

	// Access key not found
	return false, fmt.Errorf("access key %s not found for user %s", accessKeyID, username)
}

// DeactivateAccessKey deactivates a specific access key for a user
func DeactivateAccessKey(ctx context.Context, client *iam.Client, username, accessKeyID string) error {
	// First, verify the key exists
	exists, err := IsAccessKeyActiveAndExists(ctx, client, username, accessKeyID)
	if err != nil {
		// If error is "not found", return that specific error
		return err
	}
	
	// If key exists but is not active, nothing to do
	if !exists {
		return fmt.Errorf("access key %s for user %s is already inactive", accessKeyID, username)
	}

	// Update the access key status to Inactive
	updateInput := &iam.UpdateAccessKeyInput{
		UserName:    aws.String(username),
		AccessKeyId: aws.String(accessKeyID),
		Status:      types.StatusTypeInactive,
	}

	_, err = client.UpdateAccessKey(ctx, updateInput)
	if err != nil {
		return fmt.Errorf("error deactivating access key %s for user %s: %v", accessKeyID, username, err)
	}

	return nil
}

// Example usage
func main() {
	// Initialize the SDK
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("failed to load SDK config: %v", err)
	}

	// Create an IAM client
	client := iam.NewFromConfig(cfg)

	// Example for checking if a user has too many active access keys
	username := "example-user"
	hasTooMany, count, err := HasTooManyActiveAccessKeys(ctx, client, username)
	if err != nil {
		log.Fatalf("error checking access keys: %v", err)
	}
	if hasTooMany {
		fmt.Printf("User %s has too many active access keys: %d\n", username, count)
	} else {
		fmt.Printf("User %s has an acceptable number of active access keys: %d\n", username, count)
	}

	// Example for checking if a specific access key is active
	accessKeyID := "AKIAEXAMPLEKEYID123"
	isActive, err := IsAccessKeyActiveAndExists(ctx, client, username, accessKeyID)
	if err != nil {
		log.Printf("Error checking access key status: %v", err)
	} else if isActive {
		fmt.Printf("Access key %s for user %s is active\n", accessKeyID, username)
	} else {
		fmt.Printf("Access key %s for user %s is not active\n", accessKeyID, username)
	}

	// Example for deactivating an access key
	err = DeactivateAccessKey(ctx, client, username, accessKeyID)
	if err != nil {
		log.Printf("Error deactivating access key: %v", err)
	} else {
		fmt.Printf("Successfully deactivated access key %s for user %s\n", accessKeyID, username)
	}
}

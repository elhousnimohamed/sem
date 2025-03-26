func init() {
	// Add flags to the remediate command
	remediateCmd.Flags().StringVar(&resourceID, "resource-id", "", "Identifier for the resource to remediate (required)")
	remediateCmd.Flags().StringVar(&targetARN, "target-arn", "", "AWS Resource ARN to remediate (required)")

	// Mark flags as required
	remediateCmd.MarkFlagRequired("resource-id")
	remediateCmd.MarkFlagRequired("target-arn")

	// Add subcommands
	awsCmd.AddCommand(remediateCmd)
	rootCmd.AddCommand(awsCmd)
}


Run: func(cmd *cobra.Command, args []string) {
		// Load configuration
		cfg, err := config.LoadConfig()
		if err != nil {
			log.Fatalf("Failed to load configuration: %v", err)
		}

		// Extract account ID from target ARN
		parts := strings.Split(targetARN, ":")
		if len(parts) < 5 {
			log.Fatalf("Invalid target ARN format: %s", targetARN)
		}
		accountID := parts[4]

		// Assume AWS role
		awsCfg, err := auth.AssumeAWSRole(accountID, cfg.EntityName)
		if err != nil {
			log.Fatalf("Failed to assume AWS role: %v", err)
		}

		// Handle remediation
		ctx := cmd.Context()
		if err := remediation.HandleRemediation(ctx, awsCfg, resourceID, targetARN); err != nil {
			log.Fatalf("Remediation failed: %v", err)
		}

		fmt.Printf("Successfully remediated resource %s\n", resourceID)
	},


package utils

import (
    "bufio"
    "fmt"
    "os"
    "strings"
)

func ConfirmAction(actionDescription string) bool {
    reader := bufio.NewReader(os.Stdin)
    fmt.Printf("\nWARNING: %s\nType 'CONFIRM' to proceed: ", actionDescription)
    
    response, _ := reader.ReadString('\n')
    return strings.TrimSpace(response) == "CONFIRM"
}


// Confirm destructive action
    if !utils.ConfirmAction(fmt.Sprintf("You are about to PERMANENTLY DELETE IAM user: %s", username)) {
        fmt.Println("Deletion cancelled by user")
        return nil
    }
-----------------------------------------------------
package iammanagement

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// CheckUserConsoleAccess checks if an IAM user exists and has console access
func CheckUserConsoleAccess(username string) (bool, error) {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return false, fmt.Errorf("failed to load AWS configuration: %v", err)
	}

	// Create IAM client
	iamClient := iam.NewFromConfig(cfg)

	// Check if user exists
	_, err = iamClient.GetUser(context.TODO(), &iam.GetUserInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return false, fmt.Errorf("failed to get user %s: %v", username, err)
	}

	// Get login profile to check console access
	_, err = iamClient.GetLoginProfile(context.TODO(), &iam.GetLoginProfileInput{
		UserName: aws.String(username),
	})
	if err != nil {
		// If GetLoginProfile returns an error, the user doesn't have console access
		return false, nil
	}

	// User exists and has console access
	return true, nil
}

// RemoveUserConsoleAccess removes console access for an IAM user
func RemoveUserConsoleAccess(username string) error {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return fmt.Errorf("failed to load AWS configuration: %v", err)
	}

	// Create IAM client
	iamClient := iam.NewFromConfig(cfg)

	// Delete login profile to remove console access
	_, err = iamClient.DeleteLoginProfile(context.TODO(), &iam.DeleteLoginProfileInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return fmt.Errorf("failed to remove console access for user %s: %v", username, err)
	}

	return nil
}

// Example usage
func ExampleIAMUserManagement() {
	username := "example-user"

	// Check if user has console access
	hasConsoleAccess, err := CheckUserConsoleAccess(username)
	if err != nil {
		fmt.Printf("Error checking user console access: %v\n", err)
		return
	}
	fmt.Printf("User %s console access: %v\n", username, hasConsoleAccess)

	// Remove console access
	err = RemoveUserConsoleAccess(username)
	if err != nil {
		fmt.Printf("Error removing console access: %v\n", err)
		return
	}
	fmt.Printf("Removed console access for user %s\n", username)
}

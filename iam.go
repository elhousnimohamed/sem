package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// checkErr handles errors in a consistent way
func checkErr(msg string, err error) {
	if err != nil {
		log.Fatalf("[ERROR] %s: %v\n", msg, err)
	}
}

func main() {
	// Parse command-line arguments
	userArn := flag.String("user-arn", "", "ARN of the IAM user")
	oldKeyID := flag.String("old-key-id", "", "Access Key ID to delete")
	outputFile := flag.String("output", "new_access_key.txt", "File to store the new credentials")
	flag.Parse()

	if *userArn == "" || *oldKeyID == "" {
		log.Fatal("Both --user-arn and --old-key-id are required")
	}

	// Extract username from ARN
	parts := strings.Split(*userArn, "/")
	if len(parts) < 2 {
		log.Fatalf("Invalid user ARN format: %s", *userArn)
	}
	username := parts[len(parts)-1]

	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	checkErr("Unable to load AWS configuration", err)

	iamClient := iam.NewFromConfig(cfg)

	// Verify user exists
	_, err = iamClient.GetUser(context.TODO(), &iam.GetUserInput{
		UserName: aws.String(username),
	})
	checkErr(fmt.Sprintf("User %s not found", username), err)
	log.Printf("[INFO] Verified IAM user: %s\n", username)

	// Delete the old access key
	_, err = iamClient.DeleteAccessKey(context.TODO(), &iam.DeleteAccessKeyInput{
		UserName:    aws.String(username),
		AccessKeyId: aws.String(*oldKeyID),
	})
	checkErr(fmt.Sprintf("Failed to delete old access key %s", *oldKeyID), err)
	log.Printf("[INFO] Deleted old access key: %s\n", *oldKeyID)

	// Create a new access key
	newKeyOutput, err := iamClient.CreateAccessKey(context.TODO(), &iam.CreateAccessKeyInput{
		UserName: aws.String(username),
	})
	checkErr("Failed to create new access key", err)

	newKeyID := *newKeyOutput.AccessKey.AccessKeyId
	newSecret := *newKeyOutput.AccessKey.SecretAccessKey
	log.Printf("[INFO] Created new access key: %s\n", newKeyID)

	// Save credentials securely to file
	filePath, err := filepath.Abs(*outputFile)
	checkErr("Unable to resolve output file path", err)

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	checkErr("Unable to create credentials file", err)
	defer file.Close()

	_, err = fmt.Fprintf(file, "AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n", newKeyID, newSecret)
	checkErr("Unable to write to credentials file", err)

	log.Printf("[SUCCESS] New credentials saved to: %s\n", filePath)
	log.Println("[REMINDER] Rotate credentials in your environment variables or config files.")
}

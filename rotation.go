package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

const (
	rotationThresholdDays = 30
)

func main() {
	var userARN string
	fmt.Print("Enter the IAM user ARN: ")
	_, err := fmt.Scanln(&userARN)
	if err != nil {
		fmt.Println("Error reading input:", err)
		return
	}

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println("Error loading AWS configuration:", err)
		return
	}

	iamClient := iam.NewFromConfig(cfg)

	reportOutput, err := getCredentialReport(context.TODO(), iamClient)
	if err != nil {
		fmt.Println("Error getting credential report:", err)
		return
	}

	userReport, err := findUserInReport(reportOutput.Content, userARN)
	if err != nil {
		fmt.Println("Error finding user in report:", err)
		return
	}

	if !userReport.AccessKey1Active && !userReport.AccessKey2Active {
		fmt.Printf("User %s has no active access keys. No action needed.\n", userARN)
		return
	}

	// Process Access Key 1
	if userReport.AccessKey1Active {
		if userReport.AccessKey1LastUsedDate == "N/A" {
			fmt.Printf("Deleting unused active access key 1 for user %s.\n", userARN)
			err = deleteAccessKey(context.TODO(), iamClient, userARN, *userReport.AccessKey1Id)
			if err != nil {
				fmt.Println("Error deleting access key 1:", err)
			}
		} else if needsRotation(userReport.AccessKey1LastRotated) {
			fmt.Printf("Rotating access key 1 for user %s.\n", userARN)
			newCredentials, err := rotateAccessKey(context.TODO(), iamClient, userARN)
			if err != nil {
				fmt.Println("Error rotating access key 1:", err)
			} else if newCredentials != nil {
				err = downloadNewCredentials(newCredentials, userARN)
				if err != nil {
					fmt.Println("Error downloading new credentials:", err)
				}
			}
		}
	}

	// Process Access Key 2
	if userReport.AccessKey2Active {
		if userReport.AccessKey2LastUsedDate == "N/A" {
			fmt.Printf("Deleting unused active access key 2 for user %s.\n", userARN)
			err = deleteAccessKey(context.TODO(), iamClient, userARN, *userReport.AccessKey2Id)
			if err != nil {
				fmt.Println("Error deleting access key 2:", err)
			}
		} else if needsRotation(userReport.AccessKey2LastRotated) {
			fmt.Printf("Rotating access key 2 for user %s.\n", userARN)
			// We can only have two active access keys at a time. If we rotated #1, we can't rotate #2 immediately.
			// A more robust solution might involve deactivating one key and then creating a new one.
			// For this example, we'll just log a warning.
			fmt.Println("Warning: Cannot rotate access key 2 immediately as access key 1 might have been rotated. Manual intervention needed.")
		}
	}

	fmt.Println("Script execution completed.")
}

func getCredentialReport(ctx context.Context, client *iam.Client) (*iam.GetCredentialReportOutput, error) {
	_, err := client.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
	if err != nil {
		var reportNotReady *types.ReportNotReadyException
		if errors.As(err, &reportNotReady) {
			fmt.Println("Credential report not yet ready. Waiting...")
			time.Sleep(5 * time.Second) // Wait a bit before trying to get it
			return client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		}
		return nil, fmt.Errorf("failed to generate credential report: %w", err)
	}
	output, err := client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get credential report: %w", err)
	}
	return output, nil
}

type UserCredentialReport struct {
	User                     string
	Arn                      string
	AccessKey1Active         bool
	AccessKey1Id             *string
	AccessKey1LastRotated    string
	AccessKey1LastUsedDate   string
	AccessKey2Active         bool
	AccessKey2Id             *string
	AccessKey2LastRotated    string
	AccessKey2LastUsedDate   string
	PasswordLastChanged      string
	PasswordEnabled          string
	MFAActive                string
	PasswordResetRequired    string
	PasswordExpiration       string
	PasswordLastUsed         string
	PermissionsBoundary      string
	SessionTokenLastUsed     string
	Cert1Active              string
	Cert1LastRotated         string
	Cert2Active              string
	Cert2LastRotated         string
	HomeDir                  string
	Shell                    string
	LoginProfileCreateDate   string
	PasswordReusePrevention  string
	PasswordRequireUppercase string
	PasswordRequireLowercase string
	PasswordRequireNumbers   string
	PasswordRequireSymbols   string
}

func findUserInReport(reportContent []byte, userARN string) (*UserCredentialReport, error) {
	r := csv.NewReader(strings.NewReader(string(reportContent)))
	headers, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("error reading CSV headers: %w", err)
	}

	userIndex := -1
	arnIndex := -1
	for i, header := range headers {
		if header == "user" {
			userIndex = i
		}
		if header == "arn" {
			arnIndex = i
		}
	}

	if userIndex == -1 || arnIndex == -1 {
		return nil, fmt.Errorf("could not find 'user' or 'arn' column in credential report")
	}

	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("error reading CSV records: %w", err)
	}

	for _, record := range records {
		if len(record) > arnIndex && record[arnIndex] == userARN {
			report := &UserCredentialReport{}
			for i, header := range headers {
				value := ""
				if i < len(record) {
					value = record[i]
				}
				switch header {
				case "user":
					report.User = value
				case "arn":
					report.Arn = value
				case "access_key_1_active":
					report.AccessKey1Active, _ = strconv.ParseBool(strings.ToLower(value))
				case "access_key_1_id":
					if value != "N/A" {
						report.AccessKey1Id = aws.String(value)
					}
				case "access_key_1_last_rotated":
					report.AccessKey1LastRotated = value
				case "access_key_1_last_used_date":
					report.AccessKey1LastUsedDate = value
				case "access_key_2_active":
					report.AccessKey2Active, _ = strconv.ParseBool(strings.ToLower(value))
				case "access_key_2_id":
					if value != "N/A" {
						report.AccessKey2Id = aws.String(value)
					}
				case "access_key_2_last_rotated":
					report.AccessKey2LastRotated = value
				case "access_key_2_last_used_date":
					report.AccessKey2LastUsedDate = value
				// Add other fields as needed
				}
			}
			return report, nil
		}
	}

	return nil, fmt.Errorf("user with ARN '%s' not found in credential report", userARN)
}

func needsRotation(lastRotated string) bool {
	if lastRotated == "N/A" {
		return false // Never rotated, but we only rotate if active and old
	}
	t, err := time.Parse(time.RFC3339, lastRotated)
	if err != nil {
		fmt.Println("Error parsing last rotated date:", err)
		return false
	}
	return time.Now().UTC().Sub(t) > time.Duration(rotationThresholdDays*24)*time.Hour
}

func deleteAccessKey(ctx context.Context, client *iam.Client, userName string, accessKeyID string) error {
	_, err := client.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
		AccessKeyId: &accessKeyID,
		UserName:    &userName,
	})
	return err
}

func rotateAccessKey(ctx context.Context, client *iam.Client, userName string) (*types.CreateAccessKeyOutput, error) {
	// Deactivate the old key first
	userOutput, err := client.GetUser(ctx, &iam.GetUserInput{UserName: &userName})
	if err != nil {
		return nil, fmt.Errorf("failed to get user %s: %w", userName, err)
	}

	var activeKeyID *string
	if userOutput.User.AccessKeyId != nil {
		// Assuming only one active key to rotate for simplicity in this step
		activeKeyID = userOutput.User.AccessKeyId
		_, err = client.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
			AccessKeyId: activeKeyID,
			Status:      types.StatusTypeInactive,
			UserName:    &userName,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to deactivate access key %s for user %s: %w", *activeKeyID, userName, err)
		}
		fmt.Printf("Deactivated access key %s for user %s.\n", *activeKeyID, userName)
	}

	// Create a new access key
	newKeyOutput, err := client.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{
		UserName: &userName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create new access key for user %s: %w", userName, err)
	}

	// Optionally delete the deactivated key after a short delay (consider security implications)
	if activeKeyID != nil {
		time.Sleep(5 * time.Second) // Give time for the new key to propagate
		_, err = client.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
			AccessKeyId: activeKeyID,
			UserName:    &userName,
		})
		if err != nil {
			fmt.Printf("Warning: Failed to delete deactivated access key %s for user %s: %v\n", *activeKeyID, userName, err)
		} else {
			fmt.Printf("Deleted previously active access key %s for user %s.\n", *activeKeyID, userName)
		}
	}

	// Generate a new credential report to download
	_, err = client.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
	if err != nil {
		fmt.Println("Error generating new credential report:", err)
		return newKeyOutput, nil
	}
	newReportOutput, err := client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err != nil {
		fmt.Println("Error getting new credential report:", err)
		return newKeyOutput, nil
	}

	// Find the updated user in the new report to get the new credentials
	newUserReport, err := findUserInReport(newReportOutput.Content, userName)
	if err != nil {
		fmt.Println("Error finding updated user in new report:", err)
		return newKeyOutput, nil
	}

	// Return the new credentials
	if newUserReport.AccessKey1Id != nil && *newUserReport.AccessKey1Id == *newKeyOutput.AccessKey.AccessKeyId {
		return newKeyOutput, nil
	} else if newUserReport.AccessKey2Id != nil && *newUserReport.AccessKey2Id == *newKeyOutput.AccessKey.AccessKeyId {
		return newKeyOutput, nil
	} else {
		fmt.Println("Warning: Could not find the newly created access key in the updated credential report.")
		return newKeyOutput, nil
	}
}

func downloadNewCredentials(newCredentials *types.CreateAccessKeyOutput, userName string) error {
	filename := fmt.Sprintf("%s_new_credentials_%s.csv", userName, time.Now().Format("20060102_150405"))
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file %s: %w", filename, err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"User", "AccessKeyId", "SecretAccessKey"}
	err = writer.Write(headers)
	if err != nil {
		return fmt.Errorf("error writing CSV headers: %w", err)
	}

	record := []string{userName, *newCredentials.AccessKey.AccessKeyId, *newCredentials.AccessKey.SecretAccessKey}
	err = writer.Write(record)
	if err != nil {
		return fmt.Errorf("error writing CSV data: %w", err)
	}

	fmt.Printf("New credentials downloaded to %s\n", filename)
	return nil
}

func (c *IAMClient) rotateAccessKey(ctx context.Context, username, oldKeyID string) error {
	// Create new key
	newKey, err := c.createAccessKey(ctx, username)
	if err != nil {
		return err
	}

	// Write new key credentials to file
	filename := fmt.Sprintf("%s_new_credentials.txt", username)
	content := fmt.Sprintf("Access Key ID: %s\nSecret Access Key: %s\n", *newKey.AccessKeyId, *newKey.SecretAccessKey)
	err = os.WriteFile(filename, []byte(content), 0600)
	if err != nil {
		return fmt.Errorf("failed to save new credentials to file: %v", err)
	}
	fmt.Printf("New credentials saved to %s (KEEP THIS SECURE!)\n", filename)

	// Delete old key
	err = c.deleteAccessKey(ctx, username, oldKeyID)
	if err != nil {
		fmt.Printf("WARNING: Created new key but failed to delete old key %s. Manual cleanup required.\n", oldKeyID)
		return err
	}

	return nil
}

func (c *IAMClient) createAccessKey(ctx context.Context, username string) (*types.AccessKey, error) {
	result, err := c.client.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create new access key for user %s: %v", username, err)
	}
	fmt.Printf("Created new access key for user %s: %s\n", username, *result.AccessKey.AccessKeyId)
	return result.AccessKey, nil
}
func (c *IAMClient) deleteAccessKey(ctx context.Context, username, accessKeyID string) error {
	_, err := c.client.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
		UserName:    aws.String(username),
		AccessKeyId: aws.String(accessKeyID),
	})
	if err != nil {
		return fmt.Errorf("failed to delete access key %s for user %s: %v", accessKeyID, username, err)
	}
	fmt.Printf("Deleted unused access key %s for user %s\n", accessKeyID, username)
	return nil
}

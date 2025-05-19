package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
)

func main() {
	// Define command-line flags
	trailARN := flag.String("trail-arn", "", "ARN of the CloudTrail trail to configure (required)")
	flag.Parse()

	// Validate required parameters
	if *trailARN == "" {
		log.Fatal("Error: trail-arn is required")
	}

	// Extract trail name from ARN
	trailName := extractTrailNameFromARN(*trailARN)
	if trailName == "" {
		log.Fatal("Error: Could not extract trail name from ARN")
	}

	// Create an AWS session
	sess, err := session.NewSession()
	if err != nil {
		log.Fatalf("Error creating AWS session: %v", err)
	}

	// Create a CloudTrail client
	svc := cloudtrail.New(sess)

	// First, get the current trail configuration
	getTrailInput := &cloudtrail.GetTrailInput{
		Name: aws.String(trailName),
	}
	
	getTrailOutput, err := svc.GetTrail(getTrailInput)
	if err != nil {
		log.Fatalf("Error getting trail information: %v", err)
	}
	
	trail := getTrailOutput.Trail
	
	// Check if the trail is already a multi-region trail
	updateNeeded := false
	if trail.IsMultiRegionTrail == nil || !*trail.IsMultiRegionTrail {
		fmt.Println("Multi-region trail needs to be enabled")
		updateNeeded = true
	} else {
		fmt.Println("Multi-region trail is already enabled")
	}
	
	// Check if global service events are included
	if trail.IncludeGlobalServiceEvents == nil || !*trail.IncludeGlobalServiceEvents {
		fmt.Println("Global service events need to be enabled")
		updateNeeded = true
	} else {
		fmt.Println("Global service events are already included")
	}
	
	// Update trail if needed
	if updateNeeded {
		updateInput := &cloudtrail.UpdateTrailInput{
			Name:                     aws.String(trailName),
			IsMultiRegionTrail:       aws.Bool(true),
			IncludeGlobalServiceEvents: aws.Bool(true),
		}
		
		_, err = svc.UpdateTrail(updateInput)
		if err != nil {
			log.Fatalf("Error updating trail: %v", err)
		}
		fmt.Println("Successfully updated trail configuration")
	}

	// Check if logging is enabled
	statusInput := &cloudtrail.GetTrailStatusInput{
		Name: aws.String(trailName),
	}
	
	statusOutput, err := svc.GetTrailStatus(statusInput)
	if err != nil {
		log.Fatalf("Error getting trail status: %v", err)
	}
	
	// Enable logging if not already enabled
	if statusOutput.IsLogging == nil || !*statusOutput.IsLogging {
		_, err = svc.StartLogging(&cloudtrail.StartLoggingInput{
			Name: aws.String(trailName),
		})
		if err != nil {
			log.Fatalf("Error starting logging: %v", err)
		}
		fmt.Println("Successfully enabled logging")
	} else {
		fmt.Println("Logging is already enabled")
	}

	// Check event selectors
	eventSelectorsInput := &cloudtrail.GetEventSelectorsInput{
		TrailName: aws.String(trailName),
	}
	
	currentEventSelectors, err := svc.GetEventSelectors(eventSelectorsInput)
	if err != nil {
		log.Fatalf("Error getting event selectors: %v", err)
	}
	
	// Check if management events are configured correctly
	managementEventsConfigured := false
	if len(currentEventSelectors.EventSelectors) > 0 {
		for _, selector := range currentEventSelectors.EventSelectors {
			if selector.ReadWriteType != nil && 
			   *selector.ReadWriteType == "All" && 
			   selector.IncludeManagementEvents != nil && 
			   *selector.IncludeManagementEvents {
				managementEventsConfigured = true
				break
			}
		}
	}
	
	// Update event selectors if needed
	if !managementEventsConfigured {
		putEventSelectorsInput := &cloudtrail.PutEventSelectorsInput{
			TrailName: aws.String(trailName),
			EventSelectors: []*cloudtrail.EventSelector{
				{
					ReadWriteType:           aws.String("All"),
					IncludeManagementEvents: aws.Bool(true),
				},
			},
		}
		
		_, err = svc.PutEventSelectors(putEventSelectorsInput)
		if err != nil {
			log.Fatalf("Error configuring event selectors: %v", err)
		}
		fmt.Println("Successfully configured read and write management events")
	} else {
		fmt.Println("Read and write management events are already configured")
	}

	fmt.Println("\nCloudTrail Configuration Summary:")
	fmt.Printf("- Trail Name: %s\n", trailName)
	fmt.Printf("- Trail ARN: %s\n", *trailARN)
	fmt.Println("- Multi-region trail: Enabled")
	fmt.Println("- Logging: Enabled")
	fmt.Println("- Management events: Read and Write")
}

// extractTrailNameFromARN extracts the trail name from the ARN
func extractTrailNameFromARN(arn string) string {
	// ARN format: arn:aws:cloudtrail:region:account-id:trail/trail-name
	parts := strings.Split(arn, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}

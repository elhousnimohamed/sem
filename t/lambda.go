package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// PolicyAnalysisResult represents the result of analyzing and potentially modifying a Lambda policy
type PolicyAnalysisResult struct {
	FunctionARN          string    `json:"function_arn"`
	WasPubliclyAccessible bool      `json:"was_publicly_accessible"`
	ChangesRequired      bool      `json:"changes_required"`
	ChangesMade          bool      `json:"changes_made"`
	OriginalPolicy       string    `json:"original_policy,omitempty"`
	ModifiedPolicy       string    `json:"modified_policy,omitempty"`
	RemovedStatements    []string  `json:"removed_statements,omitempty"`
	Timestamp            time.Time `json:"timestamp"`
	Error                string    `json:"error,omitempty"`
}

// PolicyStatement represents an AWS policy statement
type PolicyStatement struct {
	Sid       string      `json:"Sid,omitempty"`
	Effect    string      `json:"Effect"`
	Principal interface{} `json:"Principal,omitempty"`
	Action    interface{} `json:"Action"`
	Resource  interface{} `json:"Resource,omitempty"`
	Condition interface{} `json:"Condition,omitempty"`
}

// PolicyDocument represents an AWS policy document
type PolicyDocument struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement"`
}

// LambdaPolicyManager handles Lambda policy operations
type LambdaPolicyManager struct {
	client *lambda.Client
}

// NewLambdaPolicyManager creates a new instance of LambdaPolicyManager
func NewLambdaPolicyManager(ctx context.Context) (*LambdaPolicyManager, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &LambdaPolicyManager{
		client: lambda.NewFromConfig(cfg),
	}, nil
}

// SecureLambdaFunction analyzes and secures a Lambda function's resource-based policy
func (lpm *LambdaPolicyManager) SecureLambdaFunction(ctx context.Context, functionARN string) (*PolicyAnalysisResult, error) {
	result := &PolicyAnalysisResult{
		FunctionARN: functionARN,
		Timestamp:   time.Now(),
	}

	// Validate ARN format
	if err := validateLambdaARN(functionARN); err != nil {
		result.Error = fmt.Sprintf("Invalid ARN format: %v", err)
		return result, err
	}

	// Extract function name from ARN
	functionName, err := extractFunctionName(functionARN)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to extract function name: %v", err)
		return result, err
	}

	// Retrieve the current policy
	policy, err := lpm.getPolicy(ctx, functionName)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to retrieve policy: %v", err)
		return result, err
	}

	if policy == "" {
		// No policy exists, function is not publicly accessible
		return result, nil
	}

	result.OriginalPolicy = policy

	// Parse the policy document
	var policyDoc PolicyDocument
	if err := json.Unmarshal([]byte(policy), &policyDoc); err != nil {
		result.Error = fmt.Sprintf("Failed to parse policy JSON: %v", err)
		return result, err
	}

	// Analyze the policy for public access
	publicStatements := lpm.identifyPublicStatements(policyDoc.Statement)
	result.WasPubliclyAccessible = len(publicStatements) > 0

	if !result.WasPubliclyAccessible {
		// Function is not publicly accessible
		return result, nil
	}

	result.ChangesRequired = true

	// Create a new policy with public statements removed
	securedStatements := make([]PolicyStatement, 0)
	removedStatements := make([]string, 0)

	for i, stmt := range policyDoc.Statement {
		if contains(publicStatements, i) {
			// Record removed statement for audit purposes
			stmtJSON, _ := json.Marshal(stmt)
			removedStatements = append(removedStatements, string(stmtJSON))
		} else {
			securedStatements = append(securedStatements, stmt)
		}
	}

	result.RemovedStatements = removedStatements

	// If all statements were removed, remove all permissions
	if len(securedStatements) == 0 {
		err = lpm.removeAllPermissions(ctx, functionName)
		if err != nil {
			result.Error = fmt.Sprintf("Failed to remove all permissions: %v", err)
			return result, err
		}
		result.ChangesMade = true
		result.ModifiedPolicy = ""
		return result, nil
	}

	// Create new policy document
	newPolicyDoc := PolicyDocument{
		Version:   policyDoc.Version,
		Statement: securedStatements,
	}

	newPolicyJSON, err := json.Marshal(newPolicyDoc)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to marshal new policy: %v", err)
		return result, err
	}

	result.ModifiedPolicy = string(newPolicyJSON)

	// Update the policy
	err = lpm.updatePolicy(ctx, functionName, string(newPolicyJSON))
	if err != nil {
		result.Error = fmt.Sprintf("Failed to update policy: %v", err)
		return result, err
	}

	result.ChangesMade = true
	return result, nil
}

// getPolicy retrieves the resource-based policy for a Lambda function
func (lmp *LambdaPolicyManager) getPolicy(ctx context.Context, functionName string) (string, error) {
	input := &lambda.GetPolicyInput{
		FunctionName: aws.String(functionName),
	}

	result, err := lmp.client.GetPolicy(ctx, input)
	if err != nil {
		// Check if the error is because no policy exists
		var notFoundErr *types.ResourceNotFoundException
		if errors.As(err, &notFoundErr) {
			return "", nil // No policy exists
		}
		return "", fmt.Errorf("AWS API error: %w", err)
	}

	if result.Policy == nil {
		return "", nil
	}

	return *result.Policy, nil
}

// updatePolicy updates the resource-based policy for a Lambda function
func (lpm *LambdaPolicyManager) updatePolicy(ctx context.Context, functionName, policy string) error {
	// Remove all existing permissions first
	if err := lpm.removeAllPermissions(ctx, functionName); err != nil {
		return fmt.Errorf("failed to remove existing permissions: %w", err)
	}

	// Parse the policy to add statements individually using AddPermission
	var policyDoc PolicyDocument
	if err := json.Unmarshal([]byte(policy), &policyDoc); err != nil {
		return fmt.Errorf("failed to parse policy: %w", err)
	}

	// Add each statement back using AddPermission API
	for i, stmt := range policyDoc.Statement {
		if err := lpm.addPermissionFromStatement(ctx, functionName, stmt, i); err != nil {
			return fmt.Errorf("failed to add permission for statement %d: %w", i, err)
		}
	}

	return nil
}

// addPermissionFromStatement converts a policy statement to an AddPermission call
func (lpm *LambdaPolicyManager) addPermissionFromStatement(ctx context.Context, functionName string, stmt PolicyStatement, index int) error {
	input := &lambda.AddPermissionInput{
		FunctionName: aws.String(functionName),
		StatementId:  aws.String(generateStatementId(stmt, index)),
	}

	// Extract Action - required field
	action, err := extractAction(stmt.Action)
	if err != nil {
		return fmt.Errorf("failed to extract action: %w", err)
	}
	input.Action = aws.String(action)

	// Extract Principal - required field
	principal, principalOrgID, sourceAccount, err := extractPrincipalInfo(stmt.Principal)
	if err != nil {
		return fmt.Errorf("failed to extract principal: %w", err)
	}
	input.Principal = aws.String(principal)

	// Set optional fields if present
	if principalOrgID != "" {
		input.PrincipalOrgID = aws.String(principalOrgID)
	}
	if sourceAccount != "" {
		input.SourceAccount = aws.String(sourceAccount)
	}

	// Handle EventSourceToken if present in conditions
	if eventSourceToken := extractEventSourceToken(stmt.Condition); eventSourceToken != "" {
		input.EventSourceToken = aws.String(eventSourceToken)
	}

	// Handle SourceArn if present in conditions
	if sourceArn := extractSourceArn(stmt.Condition); sourceArn != "" {
		input.SourceArn = aws.String(sourceArn)
	}

	_, err = lpm.client.AddPermission(ctx, input)
	if err != nil {
		return fmt.Errorf("AWS API error: %w", err)
	}

	return nil
}

// generateStatementId generates a statement ID, preferring the original Sid if present
func generateStatementId(stmt PolicyStatement, index int) string {
	if stmt.Sid != "" {
		return stmt.Sid
	}
	return fmt.Sprintf("statement-%d-%d", index, time.Now().Unix())
}

// extractAction extracts the action from a policy statement action field
func extractAction(action interface{}) (string, error) {
	switch a := action.(type) {
	case string:
		return a, nil
	case []interface{}:
		if len(a) > 0 {
			if str, ok := a[0].(string); ok {
				return str, nil
			}
		}
		return "", fmt.Errorf("no valid action found in array")
	default:
		return "", fmt.Errorf("unsupported action type: %T", action)
	}
}

// extractPrincipalInfo extracts principal information from the principal field
func extractPrincipalInfo(principal interface{}) (principalValue, principalOrgID, sourceAccount string, err error) {
	switch p := principal.(type) {
	case string:
		if p == "*" {
			return "*", "", "", nil
		}
		// Could be an ARN or account ID
		return p, "", "", nil
	case map[string]interface{}:
		// Handle AWS principals
		if aws, exists := p["AWS"]; exists {
			switch awsVal := aws.(type) {
			case string:
				return awsVal, "", "", nil
			case []interface{}:
				if len(awsVal) > 0 {
					if str, ok := awsVal[0].(string); ok {
						return str, "", "", nil
					}
				}
			}
		}
		// Handle Service principals
		if service, exists := p["Service"]; exists {
			if str, ok := service.(string); ok {
				return str, "", "", nil
			}
		}
		return "", "", "", fmt.Errorf("unsupported principal structure")
	default:
		return "", "", "", fmt.Errorf("unsupported principal type: %T", principal)
	}
}

// extractEventSourceToken extracts EventSourceToken from conditions
func extractEventSourceToken(condition interface{}) string {
	if condition == nil {
		return ""
	}
	
	condMap, ok := condition.(map[string]interface{})
	if !ok {
		return ""
	}
	
	if stringEquals, exists := condMap["StringEquals"]; exists {
		if seMap, ok := stringEquals.(map[string]interface{}); ok {
			if token, exists := seMap["lambda:EventSourceToken"]; exists {
				if tokenStr, ok := token.(string); ok {
					return tokenStr
				}
			}
		}
	}
	
	return ""
}

// extractSourceArn extracts SourceArn from conditions
func extractSourceArn(condition interface{}) string {
	if condition == nil {
		return ""
	}
	
	condMap, ok := condition.(map[string]interface{})
	if !ok {
		return ""
	}
	
	if arnLike, exists := condMap["ArnLike"]; exists {
		if alMap, ok := arnLike.(map[string]interface{}); ok {
			if arn, exists := alMap["AWS:SourceArn"]; exists {
				if arnStr, ok := arn.(string); ok {
					return arnStr
				}
			}
		}
	}
	
	return ""
}

// removeAllPermissions removes all permissions from a Lambda function by removing each statement
func (lpm *LambdaPolicyManager) removeAllPermissions(ctx context.Context, functionName string) error {
	// First, get the current policy to extract statement IDs
	currentPolicy, err := lpm.getPolicy(ctx, functionName)
	if err != nil {
		return fmt.Errorf("failed to get current policy: %w", err)
	}

	if currentPolicy == "" {
		return nil // No policy exists, nothing to remove
	}

	// Parse the policy to get statement IDs
	var policyDoc PolicyDocument
	if err := json.Unmarshal([]byte(currentPolicy), &policyDoc); err != nil {
		return fmt.Errorf("failed to parse current policy: %w", err)
	}

	// Remove each statement individually
	for i, stmt := range policyDoc.Statement {
		statementId := stmt.Sid
		if statementId == "" {
			// If no Sid is present, we need to try to remove by a generated pattern
			// This is tricky because we don't know what StatementId was used originally
			// We'll try common patterns
			possibleIds := []string{
				fmt.Sprintf("statement-%d", i),
				fmt.Sprintf("Statement-%d", i),
				fmt.Sprintf("stmt-%d", i),
				fmt.Sprintf("%d", i),
			}
			
			removed := false
			for _, possibleId := range possibleIds {
				if err := lpm.removePermission(ctx, functionName, possibleId); err == nil {
					removed = true
					break
				}
			}
			
			if !removed {
				// Log warning but continue - this statement might have been added differently
				fmt.Printf("Warning: Could not remove statement at index %d (no Sid and unable to guess StatementId)\n", i)
			}
		} else {
			if err := lpm.removePermission(ctx, functionName, statementId); err != nil {
				// Log error but continue with other statements
				fmt.Printf("Warning: Could not remove statement with Sid '%s': %v\n", statementId, err)
			}
		}
	}

	return nil
}

// removePermission removes a specific permission statement by StatementId
func (lpm *LambdaPolicyManager) removePermission(ctx context.Context, functionName, statementId string) error {
	input := &lambda.RemovePermissionInput{
		FunctionName: aws.String(functionName),
		StatementId:  aws.String(statementId),
	}

	_, err := lpm.client.RemovePermission(ctx, input)
	if err != nil {
		var notFoundErr *types.ResourceNotFoundException
		if errors.As(err, &notFoundErr) {
			return nil // Statement doesn't exist, which is fine
		}
		return fmt.Errorf("AWS API error: %w", err)
	}

	return nil
}

// identifyPublicStatements identifies statements that grant public access
func (lpm *LambdaPolicyManager) identifyPublicStatements(statements []PolicyStatement) []int {
	publicIndexes := make([]int, 0)

	for i, stmt := range statements {
		if stmt.Effect == "Deny" {
			continue // Deny statements don't grant access
		}

		if lpm.isPrincipalPublic(stmt.Principal) {
			publicIndexes = append(publicIndexes, i)
		}
	}

	return publicIndexes
}

// isPrincipalPublic checks if a principal grants public access
func (lpm *LambdaPolicyManager) isPrincipalPublic(principal interface{}) bool {
	switch p := principal.(type) {
	case string:
		return p == "*"
	case []interface{}:
		for _, item := range p {
			if str, ok := item.(string); ok && str == "*" {
				return true
			}
		}
	case map[string]interface{}:
		// Check AWS principals
		if aws, exists := p["AWS"]; exists {
			switch awsVal := aws.(type) {
			case string:
				return awsVal == "*"
			case []interface{}:
				for _, item := range awsVal {
					if str, ok := item.(string); ok && str == "*" {
						return true
					}
				}
			}
		}
		// Check for other service principals that might be overly permissive
		// This is a simplified check - in practice, you might want more sophisticated logic
		for _, value := range p {
			if str, ok := value.(string); ok && str == "*" {
				return true
			}
		}
	}
	return false
}

// validateLambdaARN validates that the provided ARN is a valid Lambda function ARN
func validateLambdaARN(arn string) error {
	// AWS Lambda ARN pattern: arn:aws:lambda:region:account-id:function:function-name
	arnPattern := `^arn:aws:lambda:[a-z0-9-]+:\d{12}:function:[a-zA-Z0-9-_]+(?::\$LATEST|\d+)?$`
	matched, err := regexp.MatchString(arnPattern, arn)
	if err != nil {
		return fmt.Errorf("regex error: %w", err)
	}
	if !matched {
		return fmt.Errorf("invalid Lambda function ARN format")
	}
	return nil
}

// extractFunctionName extracts the function name from a Lambda ARN
func extractFunctionName(arn string) (string, error) {
	parts := strings.Split(arn, ":")
	if len(parts) < 7 {
		return "", fmt.Errorf("invalid ARN format")
	}
	
	functionName := parts[6]
	// Handle versioned/aliased ARNs
	if len(parts) > 7 {
		functionName = parts[6] // Just the function name, not the version/alias
	}
	
	return functionName, nil
}

// contains checks if a slice contains a specific integer
func contains(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Example usage function
func main() {
	ctx := context.Background()
	
	// Initialize the policy manager
	manager, err := NewLambdaPolicyManager(ctx)
	if err != nil {
		fmt.Printf("Failed to initialize policy manager: %v\n", err)
		return
	}

	// Example Lambda function ARN - replace with actual ARN
	functionARN := "arn:aws:lambda:us-east-1:123456789012:function:my-function"

	// Secure the Lambda function
	result, err := manager.SecureLambdaFunction(ctx, functionARN)
	if err != nil {
		fmt.Printf("Error securing Lambda function: %v\n", err)
		return
	}

	// Print results
	resultJSON, _ := json.MarshalIndent(result, "", "  ")
	fmt.Printf("Security Analysis Result:\n%s\n", string(resultJSON))

	// Summary
	fmt.Printf("\nSummary:\n")
	fmt.Printf("Function: %s\n", result.FunctionARN)
	fmt.Printf("Was publicly accessible: %v\n", result.WasPubliclyAccessible)
	fmt.Printf("Changes made: %v\n", result.ChangesMade)
	if len(result.RemovedStatements) > 0 {
		fmt.Printf("Removed %d problematic statements\n", len(result.RemovedStatements))
	}
}

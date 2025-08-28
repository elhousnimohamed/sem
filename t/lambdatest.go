package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

const (
	testFunctionName = "test-lambda-security-function"
	testRoleName     = "test-lambda-security-role"
	testZipFile      = "test-function.zip"
)

// TestLambdaPolicy represents a test case for Lambda policies
type TestLambdaPolicy struct {
	Name         string
	StatementId  string
	Action       string
	Principal    string
	SourceArn    *string
	SourceAccount *string
	ShouldRemove bool // true if this policy should be removed by our security function
	Description  string
}

// TestSuite manages the entire test lifecycle
type TestSuite struct {
	ctx           context.Context
	lambdaClient  *lambda.Client
	iamClient     *iam.Client
	functionArn   string
	roleArn       string
	policyManager *LambdaPolicyManager
	testPolicies  []TestLambdaPolicy
}

// NewTestSuite creates a new test suite
func NewTestSuite(ctx context.Context) (*TestSuite, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	policyManager, err := NewLambdaPolicyManager(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy manager: %w", err)
	}

	return &TestSuite{
		ctx:           ctx,
		lambdaClient:  lambda.NewFromConfig(cfg),
		iamClient:     iam.NewFromConfig(cfg),
		policyManager: policyManager,
		testPolicies:  defineTestPolicies(),
	}, nil
}

// defineTestPolicies defines the test cases with various policy configurations
func defineTestPolicies() []TestLambdaPolicy {
	return []TestLambdaPolicy{
		{
			Name:         "PublicWildcard",
			StatementId:  "public-wildcard",
			Action:       "lambda:InvokeFunction",
			Principal:    "*",
			ShouldRemove: true,
			Description:  "Public access via wildcard principal - should be removed",
		},
		{
			Name:         "PublicWithCondition",
			StatementId:  "public-with-condition",
			Action:       "lambda:InvokeFunction", 
			Principal:    "*",
			ShouldRemove: true,
			Description:  "Public access with condition - should still be removed",
		},
		{
			Name:         "SpecificAccount",
			StatementId:  "specific-account",
			Action:       "lambda:InvokeFunction",
			Principal:    "arn:aws:iam::123456789012:root",
			ShouldRemove: false,
			Description:  "Specific AWS account access - should be kept",
		},
		{
			Name:         "ServicePrincipal",
			StatementId:  "service-principal",
			Action:       "lambda:InvokeFunction",
			Principal:    "s3.amazonaws.com",
			SourceArn:    aws.String("arn:aws:s3:::my-bucket/*"),
			ShouldRemove: false,
			Description:  "Service principal with source ARN - should be kept",
		},
		{
			Name:         "APIGateway",
			StatementId:  "apigateway-invoke",
			Action:       "lambda:InvokeFunction",
			Principal:    "apigateway.amazonaws.com",
			SourceArn:    aws.String("arn:aws:execute-api:us-east-1:123456789012:abcdef123/*"),
			ShouldRemove: false,
			Description:  "API Gateway access - should be kept",
		},
		{
			Name:         "EventBridge",
			StatementId:  "eventbridge-invoke",
			Action:       "lambda:InvokeFunction",
			Principal:    "events.amazonaws.com",
			SourceArn:    aws.String("arn:aws:events:us-east-1:123456789012:rule/my-rule"),
			ShouldRemove: false,
			Description:  "EventBridge rule access - should be kept",
		},
		{
			Name:         "PublicGetFunction",
			StatementId:  "public-get-function",
			Action:       "lambda:GetFunction",
			Principal:    "*",
			ShouldRemove: true,
			Description:  "Public GetFunction access - should be removed",
		},
	}
}

// RunFullTest executes the complete test suite
func (ts *TestSuite) RunFullTest(t *testing.T) {
	t.Log("Starting Lambda Policy Security Test Suite")

	// Setup phase
	t.Run("Setup", func(t *testing.T) {
		if err := ts.Setup(); err != nil {
			t.Fatalf("Setup failed: %v", err)
		}
		t.Logf("Test Lambda function created: %s", ts.functionArn)
	})

	// Cleanup at the end regardless of test outcome
	defer func() {
		t.Run("Cleanup", func(t *testing.T) {
			if err := ts.Cleanup(); err != nil {
				t.Errorf("Cleanup failed: %v", err)
			} else {
				t.Log("Cleanup completed successfully")
			}
		})
	}()

	// Apply test policies
	t.Run("ApplyPolicies", func(t *testing.T) {
		if err := ts.ApplyTestPolicies(); err != nil {
			t.Fatalf("Failed to apply test policies: %v", err)
		}
		t.Logf("Applied %d test policies", len(ts.testPolicies))
	})

	// Verify initial state
	t.Run("VerifyInitialState", func(t *testing.T) {
		if err := ts.VerifyInitialPolicyState(); err != nil {
			t.Fatalf("Initial state verification failed: %v", err)
		}
		t.Log("Initial policy state verified")
	})

	// Run security function
	t.Run("RunSecurityFunction", func(t *testing.T) {
		result, err := ts.policyManager.SecureLambdaFunction(ts.ctx, ts.functionArn)
		if err != nil {
			t.Fatalf("Security function failed: %v", err)
		}

		// Verify the result
		if !result.WasPubliclyAccessible {
			t.Error("Expected function to be detected as publicly accessible")
		}

		if !result.ChangesMade {
			t.Error("Expected changes to be made")
		}

		expectedRemovedCount := ts.countPoliciesThatShouldBeRemoved()
		if len(result.RemovedStatements) != expectedRemovedCount {
			t.Errorf("Expected %d statements to be removed, got %d", 
				expectedRemovedCount, len(result.RemovedStatements))
		}

		t.Logf("Security function completed: removed %d statements", len(result.RemovedStatements))
		
		// Print detailed results
		resultJSON, _ := json.MarshalIndent(result, "", "  ")
		t.Logf("Security function result:\n%s", string(resultJSON))
	})

	// Verify final state
	t.Run("VerifyFinalState", func(t *testing.T) {
		if err := ts.VerifyFinalPolicyState(); err != nil {
			t.Fatalf("Final state verification failed: %v", err)
		}
		t.Log("Final policy state verified - all public policies removed, legitimate policies preserved")
	})
}

// Setup creates the test Lambda function and IAM role
func (ts *TestSuite) Setup() error {
	// Create IAM role for Lambda
	if err := ts.createIAMRole(); err != nil {
		return fmt.Errorf("failed to create IAM role: %w", err)
	}

	// Wait a bit for role to propagate
	time.Sleep(10 * time.Second)

	// Create deployment package
	if err := ts.createDeploymentPackage(); err != nil {
		return fmt.Errorf("failed to create deployment package: %w", err)
	}

	// Create Lambda function
	if err := ts.createLambdaFunction(); err != nil {
		return fmt.Errorf("failed to create Lambda function: %w", err)
	}

	return nil
}

// createIAMRole creates an IAM role for the test Lambda function
func (ts *TestSuite) createIAMRole() error {
	assumeRolePolicy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {
					"Service": "lambda.amazonaws.com"
				},
				"Action": "sts:AssumeRole"
			}
		]
	}`

	createRoleInput := &iam.CreateRoleInput{
		RoleName:                 aws.String(testRoleName),
		AssumeRolePolicyDocument: aws.String(assumeRolePolicy),
		Description:              aws.String("Test role for Lambda policy security testing"),
	}

	result, err := ts.iamClient.CreateRole(ts.ctx, createRoleInput)
	if err != nil {
		return fmt.Errorf("failed to create IAM role: %w", err)
	}

	ts.roleArn = *result.Role.Arn

	// Attach basic Lambda execution policy
	attachPolicyInput := &iam.AttachRolePolicyInput{
		RoleName:  aws.String(testRoleName),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"),
	}

	_, err = ts.iamClient.AttachRolePolicy(ts.ctx, attachPolicyInput)
	if err != nil {
		return fmt.Errorf("failed to attach policy to role: %w", err)
	}

	return nil
}

// createDeploymentPackage creates a simple deployment package for the Lambda function
func (ts *TestSuite) createDeploymentPackage() error {
	// Create a simple Node.js Lambda function
	lambdaCode := `
exports.handler = async (event) => {
    console.log('Test Lambda function executed');
    return {
        statusCode: 200,
        body: JSON.stringify({
            message: 'Hello from test Lambda!',
            input: event
        })
    };
};`

	// Create ZIP file
	zipFile, err := os.Create(testZipFile)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Add index.js to ZIP
	file, err := zipWriter.Create("index.js")
	if err != nil {
		return fmt.Errorf("failed to create file in zip: %w", err)
	}

	_, err = file.Write([]byte(lambdaCode))
	if err != nil {
		return fmt.Errorf("failed to write to zip file: %w", err)
	}

	return nil
}

// createLambdaFunction creates the test Lambda function
func (ts *TestSuite) createLambdaFunction() error {
	// Read the deployment package
	zipData, err := os.ReadFile(testZipFile)
	if err != nil {
		return fmt.Errorf("failed to read deployment package: %w", err)
	}

	createFunctionInput := &lambda.CreateFunctionInput{
		FunctionName: aws.String(testFunctionName),
		Runtime:      types.RuntimeNodejs18x,
		Role:         aws.String(ts.roleArn),
		Handler:      aws.String("index.handler"),
		Code: &types.FunctionCode{
			ZipFile: zipData,
		},
		Description: aws.String("Test function for Lambda policy security testing"),
		Timeout:     aws.Int32(30),
	}

	result, err := ts.lambdaClient.CreateFunction(ts.ctx, createFunctionInput)
	if err != nil {
		return fmt.Errorf("failed to create Lambda function: %w", err)
	}

	ts.functionArn = *result.FunctionArn

	// Wait for function to be active
	return ts.waitForFunctionActive()
}

// waitForFunctionActive waits for the Lambda function to become active
func (ts *TestSuite) waitForFunctionActive() error {
	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		getFunctionInput := &lambda.GetFunctionInput{
			FunctionName: aws.String(testFunctionName),
		}

		result, err := ts.lambdaClient.GetFunction(ts.ctx, getFunctionInput)
		if err != nil {
			return fmt.Errorf("failed to get function status: %w", err)
		}

		if result.Configuration.State == types.StateActive {
			return nil
		}

		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("function did not become active within timeout")
}

// ApplyTestPolicies applies all test policies to the Lambda function
func (ts *TestSuite) ApplyTestPolicies() error {
	for _, policy := range ts.testPolicies {
		input := &lambda.AddPermissionInput{
			FunctionName: aws.String(testFunctionName),
			StatementId:  aws.String(policy.StatementId),
			Action:       aws.String(policy.Action),
			Principal:    aws.String(policy.Principal),
		}

		if policy.SourceArn != nil {
			input.SourceArn = policy.SourceArn
		}
		if policy.SourceAccount != nil {
			input.SourceAccount = policy.SourceAccount
		}

		_, err := ts.lambdaClient.AddPermission(ts.ctx, input)
		if err != nil {
			return fmt.Errorf("failed to add permission %s: %w", policy.Name, err)
		}
	}

	return nil
}

// VerifyInitialPolicyState verifies that all test policies were applied correctly
func (ts *TestSuite) VerifyInitialPolicyState() error {
	policy, err := ts.policyManager.getPolicy(ts.ctx, testFunctionName)
	if err != nil {
		return fmt.Errorf("failed to get initial policy: %w", err)
	}

	if policy == "" {
		return fmt.Errorf("no policy found after applying test policies")
	}

	var policyDoc PolicyDocument
	if err := json.Unmarshal([]byte(policy), &policyDoc); err != nil {
		return fmt.Errorf("failed to parse initial policy: %w", err)
	}

	expectedCount := len(ts.testPolicies)
	actualCount := len(policyDoc.Statement)

	if actualCount != expectedCount {
		return fmt.Errorf("expected %d policy statements, found %d", expectedCount, actualCount)
	}

	// Verify that public policies are detected
	publicStatements := ts.policyManager.identifyPublicStatements(policyDoc.Statement)
	expectedPublicCount := ts.countPoliciesThatShouldBeRemoved()

	if len(publicStatements) != expectedPublicCount {
		return fmt.Errorf("expected %d public statements, detected %d", expectedPublicCount, len(publicStatements))
	}

	return nil
}

// VerifyFinalPolicyState verifies that only legitimate policies remain after security function
func (ts *TestSuite) VerifyFinalPolicyState() error {
	policy, err := ts.policyManager.getPolicy(ts.ctx, testFunctionName)
	if err != nil {
		return fmt.Errorf("failed to get final policy: %w", err)
	}

	expectedKeptCount := ts.countPoliciesThatShouldBeKept()

	if policy == "" {
		if expectedKeptCount > 0 {
			return fmt.Errorf("all policies removed, but expected %d to be kept", expectedKeptCount)
		}
		return nil // No policies remaining, which is correct if all were public
	}

	var policyDoc PolicyDocument
	if err := json.Unmarshal([]byte(policy), &policyDoc); err != nil {
		return fmt.Errorf("failed to parse final policy: %w", err)
	}

	actualCount := len(policyDoc.Statement)
	if actualCount != expectedKeptCount {
		return fmt.Errorf("expected %d statements to remain, found %d", expectedKeptCount, actualCount)
	}

	// Verify no public statements remain
	publicStatements := ts.policyManager.identifyPublicStatements(policyDoc.Statement)
	if len(publicStatements) > 0 {
		return fmt.Errorf("found %d public statements after security function", len(publicStatements))
	}

	// Verify that legitimate policies are still present
	return ts.verifyLegitimateStatements(policyDoc.Statement)
}

// verifyLegitimateStatements checks that all legitimate statements are preserved
func (ts *TestSuite) verifyLegitimateStatements(statements []PolicyStatement) error {
	legitimatePolicies := make([]TestLambdaPolicy, 0)
	for _, policy := range ts.testPolicies {
		if !policy.ShouldRemove {
			legitimatePolicies = append(legitimatePolicies, policy)
		}
	}

	for _, legitPolicy := range legitimatePolicies {
		found := false
		for _, stmt := range statements {
			if ts.statementMatchesPolicy(stmt, legitPolicy) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("legitimate policy %s was incorrectly removed", legitPolicy.Name)
		}
	}

	return nil
}

// statementMatchesPolicy checks if a policy statement matches a test policy
func (ts *TestSuite) statementMatchesPolicy(stmt PolicyStatement, policy TestLambdaPolicy) bool {
	// Check action
	if !ts.actionMatches(stmt.Action, policy.Action) {
		return false
	}

	// Check principal
	if !ts.principalMatches(stmt.Principal, policy.Principal) {
		return false
	}

	return true
}

// actionMatches checks if statement action matches expected action
func (ts *TestSuite) actionMatches(stmtAction interface{}, expectedAction string) bool {
	switch a := stmtAction.(type) {
	case string:
		return a == expectedAction
	case []interface{}:
		for _, action := range a {
			if str, ok := action.(string); ok && str == expectedAction {
				return true
			}
		}
	}
	return false
}

// principalMatches checks if statement principal matches expected principal
func (ts *TestSuite) principalMatches(stmtPrincipal interface{}, expectedPrincipal string) bool {
	switch p := stmtPrincipal.(type) {
	case string:
		return p == expectedPrincipal
	case map[string]interface{}:
		if service, ok := p["Service"]; ok {
			if str, ok := service.(string); ok {
				return str == expectedPrincipal
			}
		}
		if aws, ok := p["AWS"]; ok {
			if str, ok := aws.(string); ok {
				return str == expectedPrincipal
			}
		}
	}
	return false
}

// countPoliciesThatShouldBeRemoved counts test policies that should be removed
func (ts *TestSuite) countPoliciesThatShouldBeRemoved() int {
	count := 0
	for _, policy := range ts.testPolicies {
		if policy.ShouldRemove {
			count++
		}
	}
	return count
}

// countPoliciesThatShouldBeKept counts test policies that should be kept
func (ts *TestSuite) countPoliciesThatShouldBeKept() int {
	count := 0
	for _, policy := range ts.testPolicies {
		if !policy.ShouldRemove {
			count++
		}
	}
	return count
}

// Cleanup removes all created resources
func (ts *TestSuite) Cleanup() error {
	var errors []string

	// Remove deployment package
	if err := os.Remove(testZipFile); err != nil && !os.IsNotExist(err) {
		errors = append(errors, fmt.Sprintf("failed to remove zip file: %v", err))
	}

	// Delete Lambda function
	if ts.functionArn != "" {
		deleteFunctionInput := &lambda.DeleteFunctionInput{
			FunctionName: aws.String(testFunctionName),
		}
		if _, err := ts.lambdaClient.DeleteFunction(ts.ctx, deleteFunctionInput); err != nil {
			errors = append(errors, fmt.Sprintf("failed to delete Lambda function: %v", err))
		}
	}

	// Delete IAM role (first detach policies)
	if ts.roleArn != "" {
		// Detach managed policy
		detachPolicyInput := &iam.DetachRolePolicyInput{
			RoleName:  aws.String(testRoleName),
			PolicyArn: aws.String("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"),
		}
		if _, err := ts.iamClient.DetachRolePolicy(ts.ctx, detachPolicyInput); err != nil {
			errors = append(errors, fmt.Sprintf("failed to detach role policy: %v", err))
		}

		// Delete role
		deleteRoleInput := &iam.DeleteRoleInput{
			RoleName: aws.String(testRoleName),
		}
		if _, err := ts.iamClient.DeleteRole(ts.ctx, deleteRoleInput); err != nil {
			errors = append(errors, fmt.Sprintf("failed to delete IAM role: %v", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// TestMain is the entry point for the test
func TestLambdaPolicySecurity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	testSuite, err := NewTestSuite(ctx)
	if err != nil {
		t.Fatalf("Failed to create test suite: %v", err)
	}

	testSuite.RunFullTest(t)
}

// Standalone function to run the test manually
func main() {
	ctx := context.Background()
	testSuite, err := NewTestSuite(ctx)
	if err != nil {
		fmt.Printf("Failed to create test suite: %v\n", err)
		return
	}

	// Create a mock testing.T for standalone execution
	t := &testing.T{}
	testSuite.RunFullTest(t)
}

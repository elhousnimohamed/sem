package osupgrade

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

const (
	// AXA GO Github Shared Registry organization
	GhOrganization = "ago-sharedtferegistry"
	// AWS MPI Virtual Machine Module GitHub repository
	VmRepository = "terraform-aws-vm"
	// GitHub base URL template for AXA repositories
	githubURLTemplate = "https://github.axa.com/%s/%s.git"
	// Default file permissions for temporary directories
	tempDirPerm = 0755
	// Main Terraform configuration file name
	mainTfFile = "main.tf"
)

// ProvisioningParameter represents a CloudFormation provisioning parameter
type ProvisioningParameter struct {
	Key              string `json:"key"`
	UsePreviousValue bool   `json:"use_previous_value"`
	Value            string `json:"value"`
}

// GitCloneOptions holds configuration for git clone operations
type GitCloneOptions struct {
	Organization string
	Repository   string
	Tag          string
	Token        string
}

// TerraformProcessor handles Terraform configuration processing
type TerraformProcessor struct {
	repoPath  string
	productOS string
}

// CloudFormationClient wraps AWS CloudFormation operations
type CloudFormationClient struct {
	client *cloudformation.Client
}

// NewCloudFormationClient creates a new CloudFormation client
func NewCloudFormationClient(ctx context.Context) (*CloudFormationClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	return &CloudFormationClient{
		client: cloudformation.NewFromConfig(cfg),
	}, nil
}

// CloneRepository clones the specified repository at the given tag
func CloneRepository(tag string) (string, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return "", fmt.Errorf("GITHUB_TOKEN environment variable is required")
	}

	options := GitCloneOptions{
		Organization: GhOrganization,
		Repository:   VmRepository,
		Tag:          tag,
		Token:        token,
	}

	return cloneRepositoryWithOptions(options)
}

// cloneRepositoryWithOptions performs the actual git clone operation
func cloneRepositoryWithOptions(opts GitCloneOptions) (string, error) {
	repoURL := fmt.Sprintf(githubURLTemplate, opts.Organization, opts.Repository)

	tempDir, err := createTempDirectory(opts.Repository, opts.Tag)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %w", err)
	}

	cloneOptions := &git.CloneOptions{
		URL:      repoURL,
		Progress: os.Stdout,
		Auth: &http.BasicAuth{
			Username: "token", // GitHub token authentication
			Password: opts.Token,
		},
		ReferenceName: plumbing.NewTagReferenceName(opts.Tag),
		SingleBranch:  true,
	}

	_, err = git.PlainClone(tempDir, false, cloneOptions)
	if err != nil {
		cleanup(tempDir)
		return "", fmt.Errorf("failed to checkout tag %s: %w", opts.Tag, err)
	}

	return tempDir, nil
}

// createTempDirectory creates a temporary directory with proper naming
func createTempDirectory(repository, tag string) (string, error) {
	prefix := fmt.Sprintf("%s-%s-", repository, tag)
	return os.MkdirTemp("", prefix)
}

// Cleanup removes the temporary directory and logs the operation
func Cleanup(path string) {
	cleanup(path)
}

// cleanup removes the temporary directory with proper error handling
func cleanup(path string) {
	if err := os.RemoveAll(path); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to cleanup temporary directory %s: %v\n", path, err)
	} else {
		fmt.Printf("Cleaned up temporary directory: %s\n", path)
	}
}

// ProcessRepository processes the repository to extract module information and parameters
func ProcessRepository(repoPath, productOS string) (resourceName, moduleName string, parameters []string, err error) {
	processor := &TerraformProcessor{
		repoPath:  repoPath,
		productOS: productOS,
	}

	return processor.process()
}

// process performs the main repository processing logic
func (tp *TerraformProcessor) process() (string, string, []string, error) {
	// Step 1: Extract module name and source from main.tf
	rootModulePath := filepath.Join(tp.repoPath, mainTfFile)
	moduleName, sourceValue, err := tp.getModuleAndSource(rootModulePath)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to get module name and source: %w", err)
	}

	// Step 2: Validate target directory
	targetPath := filepath.Join(tp.repoPath, sourceValue)
	if err := validateDirectory(targetPath); err != nil {
		return "", "", nil, fmt.Errorf("failed to access target directory %s: %w", targetPath, err)
	}

	// Step 3: Extract provisioning parameters from the module
	tfFilePath := filepath.Join(targetPath, mainTfFile)
	resourceName, parameters, err := extractProvisioningParameters(tfFilePath)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to extract provisioning parameters: %w", err)
	}

	return resourceName, moduleName, parameters, nil
}

// getModuleAndSource extracts module name and source from the Terraform configuration
func (tp *TerraformProcessor) getModuleAndSource(path string) (string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("failed to read %s: %w", mainTfFile, err)
	}

	file, diags := hclwrite.ParseConfig(data, mainTfFile, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return "", "", fmt.Errorf("failed to parse HCL: %s", diags)
	}

	return tp.findMatchingModule(file)
}

// findMatchingModule finds the module that matches the product OS
func (tp *TerraformProcessor) findMatchingModule(file *hclwrite.File) (string, string, error) {
	for _, block := range file.Body().Blocks() {
		if !tp.isModuleBlock(block) {
			continue
		}

		moduleName, sourceValue, matches, err := tp.extractModuleInfo(block)
		if err != nil {
			continue // Skip malformed modules
		}

		if matches {
			return moduleName, sourceValue, nil
		}
	}

	return "", "", fmt.Errorf("no module found for image_template %s", tp.productOS)
}

// isModuleBlock checks if the block is a module block with labels
func (tp *TerraformProcessor) isModuleBlock(block *hclwrite.Block) bool {
	return block.Type() == "module" && len(block.Labels()) > 0
}

// extractModuleInfo extracts module information and checks if it matches the product OS
func (tp *TerraformProcessor) extractModuleInfo(block *hclwrite.Block) (string, string, bool, error) {
	moduleName := block.Labels()[0]
	body := block.Body()

	sourceValue, err := tp.getSourceValue(body)
	if err != nil {
		return "", "", false, err
	}

	matches := tp.checkModuleMatches(body)
	return moduleName, sourceValue, matches, nil
}

// getSourceValue extracts and normalizes the source attribute value
func (tp *TerraformProcessor) getSourceValue(body *hclwrite.Body) (string, error) {
	srcAttr := body.GetAttribute("source")
	if srcAttr == nil {
		return "", fmt.Errorf("module missing source attribute")
	}

	sourceTokens := srcAttr.Expr().BuildTokens(nil)
	sourceValue := string(hclwrite.Tokens(sourceTokens).Bytes())
	
	// Clean up the source value
	sourceValue = strings.Trim(sourceValue, `"`)
	if strings.HasPrefix(sourceValue, "./") {
		sourceValue = sourceValue[2:]
	}

	return sourceValue, nil
}

// checkModuleMatches checks if the module's count condition matches the product OS
func (tp *TerraformProcessor) checkModuleMatches(body *hclwrite.Body) bool {
	countAttr := body.GetAttribute("count")
	if countAttr == nil {
		return false
	}

	countTokens := countAttr.Expr().BuildTokens(nil)
	countValue := string(hclwrite.Tokens(countTokens).Bytes())

	// Check if the count expression contains the image template string
	expectedTemplate := fmt.Sprintf(`"%s"`, tp.productOS)
	return strings.Contains(countValue, expectedTemplate)
}

// validateDirectory checks if the specified directory exists and is accessible
func validateDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("directory does not exist: %s", path)
		}
		return fmt.Errorf("failed to access directory %s: %w", path, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", path)
	}

	return nil
}

// extractProvisioningParameters parses the Terraform file and extracts provisioning parameters
func extractProvisioningParameters(filePath string) (string, []string, error) {
	if err := validateFileExists(filePath); err != nil {
		return "", nil, err
	}

	return extractWithHCL(filePath)
}

// validateFileExists checks if the specified file exists
func validateFileExists(filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("main.tf file not found: %s", filePath)
	}
	return nil
}

// extractWithHCL uses the HashiCorp HCL library to parse Terraform files
func extractWithHCL(filePath string) (string, []string, error) {
	parser := hclparse.NewParser()

	file, diags := parser.ParseHCLFile(filePath)
	if diags.HasErrors() {
		return "", nil, fmt.Errorf("failed to parse HCL file: %s", diags.Error())
	}

	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return "", nil, fmt.Errorf("failed to convert to HCL syntax body")
	}

	return processHCLBlocks(body)
}

// processHCLBlocks processes HCL blocks to find AWS Service Catalog resources
func processHCLBlocks(body *hclsyntax.Body) (string, []string, error) {
	var parameters []string
	var resourceName string

	for _, block := range body.Blocks {
		if isServiceCatalogResource(block) {
			resourceName = block.Labels[1]
			parameters = extractParametersFromBlock(block)
		}
	}

	return resourceName, parameters, nil
}

// isServiceCatalogResource checks if the block is an AWS Service Catalog provisioned product resource
func isServiceCatalogResource(block *hclsyntax.Block) bool {
	return block.Type == "resource" && 
		   len(block.Labels) >= 2 && 
		   block.Labels[0] == "aws_servicecatalog_provisioned_product"
}

// extractParametersFromBlock extracts provisioning parameters from the resource block
func extractParametersFromBlock(block *hclsyntax.Block) []string {
	var parameters []string

	for _, nestedBlock := range block.Body.Blocks {
		if nestedBlock.Type == "provisioning_parameters" {
			if attr, exists := nestedBlock.Body.Attributes["key"]; exists {
				if value, err := attr.Expr.Value(nil); err == nil && value.Type() == cty.String {
					parameters = append(parameters, value.AsString())
				}
			}
		}
	}

	return parameters
}

// GetCloudFormationStackParameters retrieves parameters from a CloudFormation stack
func GetCloudFormationStackParameters(stackARN string) (map[string]string, error) {
	ctx := context.TODO()
	client, err := NewCloudFormationClient(ctx)
	if err != nil {
		return nil, err
	}

	return client.GetStackParameters(ctx, stackARN)
}

// GetStackParameters retrieves parameters from the specified CloudFormation stack
func (cfc *CloudFormationClient) GetStackParameters(ctx context.Context, stackARN string) (map[string]string, error) {
	stackName, err := extractStackNameFromARN(stackARN)
	if err != nil {
		return nil, err
	}

	input := &cloudformation.DescribeStacksInput{
		StackName: aws.String(stackName),
	}

	result, err := cfc.client.DescribeStacks(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe CloudFormation stack: %w", err)
	}

	if len(result.Stacks) == 0 {
		return nil, fmt.Errorf("CloudFormation stack not found: %s", stackName)
	}

	parameters := extractParametersFromStack(result.Stacks[0])
	if len(parameters) == 0 {
		return nil, fmt.Errorf("no parameters found in CloudFormation stack: %s", stackName)
	}

	return parameters, nil
}

// extractStackNameFromARN extracts the stack name from a CloudFormation stack ARN
func extractStackNameFromARN(stackARN string) (string, error) {
	// ARN format: arn:aws:cloudformation:region:account:stack/stack-name/stack-id
	parts := strings.Split(stackARN, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid CloudFormation stack ARN format: %s", stackARN)
	}
	return parts[1], nil
}

// extractParametersFromStack extracts parameters from a CloudFormation stack
func extractParametersFromStack(stack cloudformation.Stack) map[string]string {
	parameters := make(map[string]string)

	for _, param := range stack.Parameters {
		if param.ParameterKey != nil && param.ParameterValue != nil {
			key := aws.ToString(param.ParameterKey)
			value := aws.ToString(param.ParameterValue)
			parameters[key] = value
		}
	}

	return parameters
}

// ReorderParameters reorders provisioning parameters according to the specified order
func ReorderParameters(parameters map[string]string, order []string) []ProvisioningParameter {
	var result []ProvisioningParameter

	for _, key := range order {
		value, exists := parameters[key]
		if !exists {
			fmt.Fprintf(os.Stderr, "Warning: Parameter '%s' not found in provisioned product\n", key)
			continue
		}

		param := ProvisioningParameter{
			Key:              key,
			UsePreviousValue: false,
			Value:            getParameterValue(key, value),
		}

		result = append(result, param)
	}

	return result
}

// getParameterValue returns the appropriate value for special parameters
func getParameterValue(key, value string) string {
	// Hostname and PrimaryIP should be empty for new deployments
	if key == "Hostname" || key == "PrimaryIP" {
		return ""
	}
	return value
}

// ReplaceModule replaces the resource name in a Terraform module string
// while preserving the module structure and any indexing
func ReplaceModule(module, resourceName string) string {
	lastModuleIndex := strings.LastIndex(module, ".module.")
	if lastModuleIndex == -1 {
		return module // No .module. found, return original
	}

	prefix := module[:lastModuleIndex+8] // +8 to include ".module."
	remainder := module[lastModuleIndex+8:]

	// Find where the resource name ends (either at '[' or end of string)
	endIndex := len(remainder)
	if bracketIndex := strings.Index(remainder, "["); bracketIndex != -1 {
		endIndex = bracketIndex
	}

	suffix := remainder[endIndex:]
	return prefix + resourceName + suffix
}

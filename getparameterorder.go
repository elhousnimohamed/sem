package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// Config holds the input parameters for the program
type Config struct {
	Organization string
	Repository   string
	Tag          string
	Subdirectory string
}

// ProvisioningParameter represents a parameter found in the Terraform resource
type ProvisioningParameter struct {
	Key   string
	Value string
}

func main() {
	// Example usage - in a real application, these would come from command line args or config
	config := Config{
		Organization: "example-org",
		Repository:   "example-repo",
		Tag:          "v1.0.0",
		Subdirectory: "terraform/modules/service-catalog",
	}

	// Parse command line arguments if provided
	if len(os.Args) >= 5 {
		config.Organization = os.Args[1]
		config.Repository = os.Args[2]
		config.Tag = os.Args[3]
		config.Subdirectory = os.Args[4]
	} else {
		fmt.Println("Usage: go run main.go <organization> <repository> <tag> <subdirectory>")
		fmt.Println("Using example values for demonstration...")
	}

	// Execute the main workflow
	if err := processRepository(config); err != nil {
		log.Fatalf("Error processing repository: %v", err)
	}
}

// processRepository orchestrates the entire workflow
func processRepository(config Config) error {
	fmt.Printf("Processing repository: %s/%s at tag %s\n", config.Organization, config.Repository, config.Tag)

	// Step 1: Clone the repository
	repoPath, err := cloneRepository(config)
	if err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}
	defer cleanup(repoPath)

	// Step 2: Navigate to the specified subdirectory
	targetPath := filepath.Join(repoPath, config.Subdirectory)
	if err := validateDirectory(targetPath); err != nil {
		return fmt.Errorf("failed to access subdirectory: %w", err)
	}

	// Step 3: Process the main.tf file
	tfFilePath := filepath.Join(targetPath, "main.tf")
	parameters, err := extractProvisioningParameters(tfFilePath)
	if err != nil {
		return fmt.Errorf("failed to extract provisioning parameters: %w", err)
	}

	// Step 4: Display results
	displayResults(parameters)

	return nil
}

func cloneRepository(config Config) (string, error) {
	repoURL := fmt.Sprintf("https://github.com/%s/%s.git", config.Organization, config.Repository)
	
	// Create a temporary directory for cloning
	tempDir, err := os.MkdirTemp("", fmt.Sprintf("%s-%s-", config.Repository, config.Tag))
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	fmt.Printf("Cloning repository from %s to %s\n", repoURL, tempDir)

	// Try to clone directly with the specific reference first
	repo, err := git.PlainClone(tempDir, false, &git.CloneOptions{
		URL:           repoURL,
		Progress:      os.Stdout,
		ReferenceName: plumbing.NewTagReferenceName(config.Tag),
		SingleBranch:  true,
	})
	
	if err != nil {
		// If direct tag clone fails, clone the full repo and checkout manually
		fmt.Printf("Direct tag clone failed, trying full clone and checkout: %v\n", err)
		
		// Remove the failed directory
		os.RemoveAll(tempDir)
		
		// Create new temp directory
		tempDir, err = os.MkdirTemp("", fmt.Sprintf("%s-%s-", config.Repository, config.Tag))
		if err != nil {
			return "", fmt.Errorf("failed to create temp directory: %w", err)
		}
		
		// Clone the repository without specifying a reference
		repo, err = git.PlainClone(tempDir, false, &git.CloneOptions{
			URL:      repoURL,
			Progress: os.Stdout,
		})
		if err != nil {
			cleanup(tempDir)
			return "", fmt.Errorf("failed to clone repository: %w", err)
		}

		// Get the working tree
		worktree, err := repo.Worktree()
		if err != nil {
			cleanup(tempDir)
			return "", fmt.Errorf("failed to get worktree: %w", err)
		}

		// Checkout the specific tag
		fmt.Printf("Checking out tag: %s\n", config.Tag)
		
		// First, try to resolve the tag to get its commit hash
		tagRef := plumbing.NewTagReferenceName(config.Tag)
		tagObject, err := repo.Reference(tagRef, true)
		if err != nil {
			// If tag reference fails, try resolving as a direct hash or lightweight tag
			hash, hashErr := repo.ResolveRevision(plumbing.Revision(config.Tag))
			if hashErr != nil {
				// Try as a branch reference
				branchRef := plumbing.NewBranchReferenceName(config.Tag)
				err = worktree.Checkout(&git.CheckoutOptions{
					Branch: branchRef,
					Force:  true, // Force checkout to override any unstaged changes
				})
				if err != nil {
					cleanup(tempDir)
					return "", fmt.Errorf("failed to checkout tag/branch %s (tried tag, hash, and branch): tag_err=%v, hash_err=%v, branch_err=%v", 
						config.Tag, err, hashErr, err)
				}
			} else {
				// Checkout using the resolved hash
				err = worktree.Checkout(&git.CheckoutOptions{
					Hash:  *hash,
					Force: true, // Force checkout to override any unstaged changes
				})
				if err != nil {
					cleanup(tempDir)
					return "", fmt.Errorf("failed to checkout commit %s: %w", hash.String(), err)
				}
			}
		} else {
			// Checkout using the tag reference
			err = worktree.Checkout(&git.CheckoutOptions{
				Hash:  tagObject.Hash(),
				Force: true, // Force checkout to override any unstaged changes
			})
			if err != nil {
				cleanup(tempDir)
				return "", fmt.Errorf("failed to checkout tag %s: %w", config.Tag, err)
			}
		}
	}

	return tempDir, nil
}
// validateDirectory checks if the specified directory exists
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
func extractProvisioningParameters(filePath string) ([]ProvisioningParameter, error) {
	fmt.Printf("Processing Terraform file: %s\n", filePath)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("main.tf file not found: %s", filePath)
	}

	// Try HCL parsing first (more robust)
	parameters, err := extractWithHCL(filePath)
	if err != nil {
		fmt.Printf("HCL parsing failed, falling back to regex parsing: %v\n", err)
		// Fallback to regex-based parsing
		return extractWithRegex(filePath)
	}

	return parameters, nil
}

// extractWithHCL uses the HashiCorp HCL library to parse Terraform files
func extractWithHCL(filePath string) ([]ProvisioningParameter, error) {
	parser := hclparse.NewParser()
	
	// Parse the HCL file
	file, diags := parser.ParseHCLFile(filePath)
	if diags.HasErrors() {
		return nil, fmt.Errorf("failed to parse HCL file: %s", diags.Error())
	}

	// Convert to syntax tree
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("failed to convert to HCL syntax body")
	}

	var parameters []ProvisioningParameter

	// Iterate through blocks to find aws_servicecatalog_provisioned_product resources
	for _, block := range body.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && 
		   block.Labels[0] == "aws_servicecatalog_provisioned_product" {
			
			fmt.Printf("Found aws_servicecatalog_provisioned_product resource: %s\n", block.Labels[1])
			
			// Look for provisioning_parameters attribute
			if attr, exists := block.Body.Attributes["provisioning_parameters"]; exists {
				params, err := parseProvisioningParametersFromHCL(attr)
				if err != nil {
					fmt.Printf("Warning: failed to parse provisioning_parameters: %v\n", err)
					continue
				}
				parameters = append(parameters, params...)
			}
		}
	}

	return parameters, nil
}

// parseProvisioningParametersFromHCL extracts parameters from HCL attribute
func parseProvisioningParametersFromHCL(attr *hclsyntax.Attribute) ([]ProvisioningParameter, error) {
	var parameters []ProvisioningParameter

	// Handle object construction expression
	if objExpr, ok := attr.Expr.(*hclsyntax.ObjectConsExpr); ok {
		for _, item := range objExpr.Items {
			key, err := extractStringFromExpr(item.KeyExpr)
			if err != nil {
				continue
			}
			
			value, err := extractStringFromExpr(item.ValueExpr)
			if err != nil {
				continue
			}

			parameters = append(parameters, ProvisioningParameter{
				Key:   key,
				Value: value,
			})
		}
	}

	return parameters, nil
}

// extractStringFromExpr extracts string value from HCL expression
func extractStringFromExpr(expr hclsyntax.Expression) (string, error) {
	switch e := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
		return e.Val.AsString(), nil
	case *hclsyntax.TemplateExpr:
		// For template expressions, try to extract parts or return a placeholder
		if len(e.Parts) > 0 {
			// If it's a simple template with one literal part, extract it
			if len(e.Parts) == 1 {
				if litExpr, ok := e.Parts[0].(*hclsyntax.LiteralValueExpr); ok {
					return litExpr.Val.AsString(), nil
				}
			}
		}
		// For complex templates, return a representation
		return fmt.Sprintf("${...template...}"), nil
	case *hclsyntax.ScopeTraversalExpr:
		// Handle variable references like var.something
		return e.Traversal.RootName(), nil
	case *hclsyntax.FunctionCallExpr:
		// Handle function calls
		return fmt.Sprintf("%s(...)", e.Name), nil
	default:
		// For other expressions, we can't easily extract the value
		// Return a generic placeholder or the expression type
		return fmt.Sprintf("<%T>", expr), nil
	}
}

// extractWithRegex uses regex parsing as a fallback method
func extractWithRegex(filePath string) ([]ProvisioningParameter, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var parameters []ProvisioningParameter
	scanner := bufio.NewScanner(file)
	
	// Regex patterns
	resourcePattern := regexp.MustCompile(`resource\s+"aws_servicecatalog_provisioned_product"\s+"([^"]+)"\s*{`)
	provisioningPattern := regexp.MustCompile(`provisioning_parameters\s*=\s*{`)
	paramPattern := regexp.MustCompile(`^\s*([^=\s]+)\s*=\s*(.+)$`)
	
	inResource := false
	inProvisioning := false
	braceCount := 0
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		
		// Check for resource block
		if resourcePattern.MatchString(line) {
			inResource = true
			fmt.Printf("Found aws_servicecatalog_provisioned_product resource\n")
			continue
		}
		
		if !inResource {
			continue
		}
		
		// Check for provisioning_parameters block
		if provisioningPattern.MatchString(line) {
			inProvisioning = true
			braceCount = 1
			continue
		}
		
		if !inProvisioning {
			continue
		}
		
		// Count braces to track nested blocks
		braceCount += strings.Count(line, "{") - strings.Count(line, "}")
		
		// If we've closed all braces, we're done with provisioning_parameters
		if braceCount <= 0 {
			break
		}
		
		// Extract parameter
		if matches := paramPattern.FindStringSubmatch(line); matches != nil {
			key := strings.TrimSpace(matches[1])
			value := strings.TrimSpace(matches[2])
			
			// Clean up the value (remove quotes, trailing commas)
			value = strings.Trim(value, `"'`)
			value = strings.TrimSuffix(value, ",")
			
			parameters = append(parameters, ProvisioningParameter{
				Key:   key,
				Value: value,
			})
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	
	return parameters, nil
}

// displayResults prints the extracted parameters
func displayResults(parameters []ProvisioningParameter) {
	fmt.Printf("\n=== Extracted Provisioning Parameters ===\n")
	
	if len(parameters) == 0 {
		fmt.Println("No provisioning parameters found.")
		return
	}
	
	fmt.Printf("Found %d provisioning parameters:\n\n", len(parameters))
	
	for i, param := range parameters {
		fmt.Printf("%d. Key: %s\n", i+1, param.Key)
		fmt.Printf("   Value: %s\n\n", param.Value)
	}
}

// cleanup removes the temporary directory
func cleanup(path string) {
	if err := os.RemoveAll(path); err != nil {
		fmt.Printf("Warning: failed to cleanup temporary directory %s: %v\n", path, err)
	} else {
		fmt.Printf("Cleaned up temporary directory: %s\n", path)
	}
}

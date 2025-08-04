package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// TerraformModuleParser provides functionality to parse Terraform files
type TerraformModuleParser struct {
	parser *hclparse.Parser
}

// NewTerraformModuleParser creates a new instance of TerraformModuleParser
func NewTerraformModuleParser() *TerraformModuleParser {
	return &TerraformModuleParser{
		parser: hclparse.NewParser(),
	}
}

// GetModuleVersion extracts the version of a specific module from a Terraform file
func (tmp *TerraformModuleParser) GetModuleVersion(filePath, moduleName string) (string, error) {
	// Validate input parameters
	if filePath == "" {
		return "", fmt.Errorf("file path cannot be empty")
	}
	if moduleName == "" {
		return "", fmt.Errorf("module name cannot be empty")
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "", fmt.Errorf("file does not exist: %s", filePath)
	}

	// Parse the Terraform file
	file, diags := tmp.parser.ParseHCLFile(filePath)
	if diags.HasErrors() {
		return "", fmt.Errorf("failed to parse HCL file: %s", diags.Error())
	}

	if file == nil || file.Body == nil {
		return "", fmt.Errorf("parsed file is empty or invalid")
	}

	// Cast to hclsyntax.Body to access the underlying structure
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return "", fmt.Errorf("unable to parse file body as HCL syntax")
	}

	// Look for module blocks
	for _, block := range body.Blocks {
		if block.Type == "module" && len(block.Labels) > 0 && block.Labels[0] == moduleName {
			// Found the target module, now extract the version
			version, err := tmp.extractVersionFromBlock(block)
			if err != nil {
				return "", fmt.Errorf("failed to extract version from module '%s': %w", moduleName, err)
			}
			return version, nil
		}
	}

	return "", fmt.Errorf("module '%s' not found in file '%s'", moduleName, filePath)
}

// extractVersionFromBlock extracts the version attribute from a module block
func (tmp *TerraformModuleParser) extractVersionFromBlock(block *hclsyntax.Block) (string, error) {
	for name, attr := range block.Body.Attributes {
		if name == "version" {
			// Evaluate the expression to get the actual value
			val, diags := attr.Expr.Value(nil)
			if diags.HasErrors() {
				return "", fmt.Errorf("failed to evaluate version expression: %s", diags.Error())
			}

			// Check if the value is a string
			if val.Type().FriendlyName() != "string" {
				return "", fmt.Errorf("version attribute is not a string")
			}

			return val.AsString(), nil
		}
	}

	return "", fmt.Errorf("version attribute not found in module block")
}

// GetModuleVersionSimple is a convenience function that creates a parser and gets the version
func GetModuleVersionSimple(filePath, moduleName string) (string, error) {
	parser := NewTerraformModuleParser()
	return parser.GetModuleVersion(filePath, moduleName)
}

// Example usage
func main() {
	// Example usage of the function
	filePath := "main.tf"
	moduleName := "iam"

	version, err := GetModuleVersionSimple(filePath, moduleName)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Module '%s' version: %s\n", moduleName, version)
}

// Alternative implementation using string parsing (less robust but no external dependencies)
/*
package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func GetModuleVersionRegex(filePath, moduleName string) (string, error) {
	if filePath == "" {
		return "", fmt.Errorf("file path cannot be empty")
	}
	if moduleName == "" {
		return "", fmt.Errorf("module name cannot be empty")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inTargetModule := false
	braceCount := 0

	// Regex patterns
	modulePattern := regexp.MustCompile(`^\s*module\s+"` + regexp.QuoteMeta(moduleName) + `"\s*{`)
	versionPattern := regexp.MustCompile(`^\s*version\s*=\s*"([^"]+)"`)

	for scanner.Scan() {
		line := scanner.Text()
		
		// Check if we're entering the target module
		if modulePattern.MatchString(line) {
			inTargetModule = true
			braceCount = 1
			continue
		}

		if inTargetModule {
			// Count braces to track module scope
			braceCount += strings.Count(line, "{") - strings.Count(line, "}")
			
			// If we've closed all braces, we're out of the module
			if braceCount <= 0 {
				break
			}

			// Look for version attribute
			if matches := versionPattern.FindStringSubmatch(line); matches != nil {
				return matches[1], nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading file: %w", err)
	}

	if !inTargetModule {
		return "", fmt.Errorf("module '%s' not found in file '%s'", moduleName, filePath)
	}

	return "", fmt.Errorf("version attribute not found in module '%s'", moduleName)
}
*/

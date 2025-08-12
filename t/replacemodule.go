package main

import (
	"fmt"
	"regexp"
	"strings"
)

// replaceResourceName replaces the resource name in a Terraform module string
// while preserving the module structure and any indexing
func replaceResourceName(module, resourceName string) string {
	// Pattern to match the last occurrence of .module.{resourceName}
	// This handles cases where there might be multiple .module. parts
	// The pattern captures everything before the last .module. and everything after the resource name
	
	// Find the last occurrence of ".module."
	lastModuleIndex := strings.LastIndex(module, ".module.")
	if lastModuleIndex == -1 {
		// No .module. found, return original string
		return module
	}
	
	// Extract the part before the last .module.
	prefix := module[:lastModuleIndex+8] // +8 to include ".module."
	
	// Extract the part after .module.
	remainder := module[lastModuleIndex+8:]
	
	// Find where the resource name ends (either at '[' or end of string)
	endIndex := len(remainder)
	if bracketIndex := strings.Index(remainder, "["); bracketIndex != -1 {
		endIndex = bracketIndex
	}
	
	// Replace the resource name part
	suffix := remainder[endIndex:]
	
	return prefix + resourceName + suffix
}

// Alternative implementation using regex for more complex cases
func replaceResourceNameRegex(module, resourceName string) string {
	// Pattern explanation:
	// (.*\.module\.) - captures everything up to and including the last .module.
	// ([^.\[]+)       - captures the resource name (non-greedy, stops at . or [)
	// (\[.*\])?       - optionally captures any indexing brackets
	// (.*)            - captures anything remaining
	
	re := regexp.MustCompile(`^(.*\.module\.)([^.\[]+)(\[.*\])?(.*?)$`)
	
	matches := re.FindStringSubmatch(module)
	if len(matches) < 3 {
		// Pattern didn't match, return original
		return module
	}
	
	// Reconstruct the string with the new resource name
	result := matches[1] + resourceName
	if len(matches) > 3 && matches[3] != "" {
		result += matches[3] // Add indexing if present
	}
	if len(matches) > 4 && matches[4] != "" {
		result += matches[4] // Add any remaining part
	}
	
	return result
}

func main() {
	// Test cases
	testCases := []struct {
		module       string
		resourceName string
		expected     string
	}{
		{
			module:       "module.linux_single.module.CreateRedhat7VmBase[0]",
			resourceName: "CreateWindows2012VmBase",
			expected:     "module.linux_single.module.CreateWindows2012VmBase[0]",
		},
		{
			module:       `module.linux_foreach["vm1"].module.CreateRedhat8VmBase[0]`,
			resourceName: "CreateWindows2012VmBase",
			expected:     `module.linux_foreach["vm1"].module.CreateWindows2012VmBase[0]`,
		},
		{
			module:       "module.linux_count[0].module.CreateRedhat8VmBase[0]",
			resourceName: "CreateWindows2012VmBase",
			expected:     "module.linux_count[0].module.CreateWindows2012VmBase[0]",
		},
		{
			module:       "module.simple.module.OldResourceName",
			resourceName: "NewResourceName",
			expected:     "module.simple.module.NewResourceName",
		},
		{
			module:       `module.complex["key"].module.ResourceName[123].something`,
			resourceName: "NewResource",
			expected:     `module.complex["key"].module.NewResource[123].something`,
		},
	}
	
	fmt.Println("Testing String-based Implementation:")
	fmt.Println(strings.Repeat("=", 50))
	
	for i, tc := range testCases {
		result := replaceResourceName(tc.module, tc.resourceName)
		status := "✓"
		if result != tc.expected {
			status = "✗"
		}
		
		fmt.Printf("Test %d: %s\n", i+1, status)
		fmt.Printf("Input:    %s\n", tc.module)
		fmt.Printf("Expected: %s\n", tc.expected)
		fmt.Printf("Got:      %s\n", result)
		fmt.Println()
	}
	
	fmt.Println("Testing Regex Implementation:")
	fmt.Println(strings.Repeat("=", 50))
	
	for i, tc := range testCases {
		result := replaceResourceNameRegex(tc.module, tc.resourceName)
		status := "✓"
		if result != tc.expected {
			status = "✗"
		}
		
		fmt.Printf("Test %d: %s\n", i+1, status)
		fmt.Printf("Input:    %s\n", tc.module)
		fmt.Printf("Expected: %s\n", tc.expected)
		fmt.Printf("Got:      %s\n", result)
		fmt.Println()
	}
	
	// Interactive example
	fmt.Println("Interactive Examples:")
	fmt.Println(strings.Repeat("=", 50))
	
	examples := []struct {
		module       string
		resourceName string
	}{
		{"module.web.module.CreateUbuntuVm[0]", "CreateCentOSVm"},
		{`module.database["primary"].module.CreateMySQLInstance`, "CreatePostgreSQLInstance"},
		{"module.cluster[2].module.CreateK8sNode[1]", "CreateDockerNode"},
	}
	
	for _, example := range examples {
		fmt.Printf("Module: %s\n", example.module)
		fmt.Printf("New Resource Name: %s\n", example.resourceName)
		fmt.Printf("Result: %s\n", replaceResourceName(example.module, example.resourceName))
		fmt.Println()
	}
}

// Function that can be imported and used in other packages
func ReplaceModuleResourceName(module, resourceName string) string {
	return replaceResourceName(module, resourceName)
}

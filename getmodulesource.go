package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/terraform-config-inspect/tfconfig"
)

type ModuleInfo struct {
	Name   string
	Source string
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <image_template>")
		fmt.Println("Example: go run main.go EC2MutableRedhat8Base")
		os.Exit(1)
	}

	imageTemplate := os.Args[1]
	
	moduleInfo, err := findModuleByImageTemplate(".", imageTemplate)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if moduleInfo == nil {
		fmt.Printf("No module found for image_template: %s\n", imageTemplate)
		os.Exit(1)
	}

	fmt.Printf("Module Name: %s\n", moduleInfo.Name)
	fmt.Printf("Source: %s\n", moduleInfo.Source)
}

func findModuleByImageTemplate(configPath, imageTemplate string) (*ModuleInfo, error) {
	// Load the Terraform module configuration
	module, diags := tfconfig.LoadModule(configPath)
	if diags.HasErrors() {
		return nil, fmt.Errorf("failed to load Terraform module: %s", diags.Error())
	}

	// Iterate through all module calls
	for name, moduleCall := range module.ModuleCalls {
		// Print the moduleCall structure to debug
		fmt.Printf("Debug - Module: %s, Source: %s\n", name, moduleCall.Source)
		fmt.Printf("Debug - ModuleCall fields: %+v\n", moduleCall)
		
		// Check if the module source or name contains our image template pattern
		// This is a simple fallback approach
		if strings.Contains(strings.ToLower(name), strings.ToLower(imageTemplate)) ||
		   strings.Contains(strings.ToLower(moduleCall.Source), strings.ToLower(imageTemplate)) {
			return &ModuleInfo{
				Name:   name,
				Source: moduleCall.Source,
			}, nil
		}
	}

	return nil, nil
}

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
		// Check if the module call has a count expression that references our image template
		if moduleCall.Count != nil {
			// Get the count expression as string and check if it contains our image template
			countExpr := strings.TrimSpace(moduleCall.Count.String())
			
			// Check if this count expression references our target image template
			if strings.Contains(countExpr, fmt.Sprintf(`"%s"`, imageTemplate)) {
				return &ModuleInfo{
					Name:   name,
					Source: moduleCall.Source,
				}, nil
			}
		}
		
		// Also check for_each if present (though your example uses count)
		if moduleCall.ForEach != nil {
			forEachExpr := strings.TrimSpace(moduleCall.ForEach.String())
			if strings.Contains(forEachExpr, fmt.Sprintf(`"%s"`, imageTemplate)) {
				return &ModuleInfo{
					Name:   name,
					Source: moduleCall.Source,
				}, nil
			}
		}
	}

	return nil, nil
}

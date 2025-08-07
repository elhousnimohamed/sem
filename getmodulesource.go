package main

import (
	"fmt"
	"os"
	"strings"

	config "github.com/hashicorp/terraform-config-inspect/tfconfig"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <ImageTemplate>")
		os.Exit(1)
	}
	imageTemplate := os.Args[1]

	module, diag := config.LoadModule(".")
	if diag.Err() != nil {
		fmt.Printf("Error loading Terraform module: %v\n", diag.Err())
		os.Exit(1)
	}

	for name, mod := range module.ModuleCalls {
		// Check if count expression is based on the image template
		if mod.CountExpr != nil && strings.Contains(mod.CountExpr.Expr().Range().Content, imageTemplate) {
			fmt.Printf("Module Name: %s\n", name)
			fmt.Printf("Source Path: %s\n", mod.Source)
			return
		}
	}

	fmt.Printf("No module found for image template: %s\n", imageTemplate)
}

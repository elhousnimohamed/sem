package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <ImageTemplate>")
		os.Exit(1)
	}
	targetImage := os.Args[1]

	parser := hclparse.NewParser()

	file, diag := parser.ParseHCLFile("main.tf")
	if diag.HasErrors() {
		fmt.Printf("Failed to parse file: %s\n", diag.Error())
		os.Exit(1)
	}

	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		fmt.Println("Failed to cast file body to hclsyntax.Body")
		os.Exit(1)
	}

	for _, block := range body.Blocks {
		if block.Type != "module" || len(block.Labels) != 1 {
			continue
		}

		moduleName := block.Labels[0]
		blockBody := block.Body

		attrs := blockBody.Attributes
		countAttr, hasCount := attrs["count"]
		sourceAttr, hasSource := attrs["source"]

		if !hasCount || !hasSource {
			continue
		}

		// Look for the image_template string in the count expression
		countExpr := countAttr.Expr.Range().Content
		src, _ := sourceAttr.Expr.Value(nil)

		// For precise parsing, extract the expression string and evaluate if it contains the target image template
		tokens := hclsyntax.ExprAsKeywordList(countAttr.Expr)
		if strings.Contains(countExpr, targetImage) {
			source, _ := src.AsString()
			fmt.Println("Module Name:", moduleName)
			fmt.Println("Source Path:", source)
			return
		}
	}

	fmt.Println("No module found for image template:", targetImage)
}

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <terraform-file> <module-name>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s main.tf linux_single\n", os.Args[0])
		os.Exit(1)
	}

	inputFile := os.Args[1]
	moduleName := os.Args[2]

	// Read the input file
	content, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Parse the HCL file
	file, diags := hclwrite.ParseConfig(content, inputFile, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		fmt.Fprintf(os.Stderr, "Error parsing HCL: %v\n", diags)
		os.Exit(1)
	}

	// Find and modify the specified module
	modified := false
	rootBody := file.Body()

	for _, block := range rootBody.Blocks() {
		if block.Type() == "module" && len(block.Labels()) > 0 && block.Labels()[0] == moduleName {
			modified = processModuleBlock(block)
			break
		}
	}

	if !modified {
		fmt.Fprintf(os.Stderr, "Module '%s' not found in %s\n", moduleName, inputFile)
		os.Exit(1)
	}

	// Generate output filename
	ext := filepath.Ext(inputFile)
	base := strings.TrimSuffix(inputFile, ext)
	outputFile := base + ext + ".example"

	// Write the modified content to the output file
	err = os.WriteFile(outputFile, file.Bytes(), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully processed module '%s' and saved to '%s'\n", moduleName, outputFile)
}

func processModuleBlock(moduleBlock *hclwrite.Block) bool {
	moduleBody := moduleBlock.Body()
	
	// Look for parameter_group attribute
	paramGroupAttr := moduleBody.GetAttribute("parameter_group")
	if paramGroupAttr == nil {
		fmt.Fprintf(os.Stderr, "parameter_group not found in module\n")
		return false
	}

	// Get the expression value
	expr := paramGroupAttr.Expr()
	
	// Parse the expression as HCL syntax to work with it
	src := hclwrite.Format(expr.BuildTokens(nil).Bytes())
	parsed, diags := hclsyntax.ParseExpression(src, "", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		fmt.Fprintf(os.Stderr, "Error parsing parameter_group expression: %v\n", diags)
		return false
	}

	// Check if it's an object constructor expression (map)
	objExpr, ok := parsed.(*hclsyntax.ObjectConsExpr)
	if !ok {
		fmt.Fprintf(os.Stderr, "parameter_group is not a map/object\n")
		return false
	}

	// Create a new object expression with modified values
	newItems := make([]hclwrite.ObjectAttrTokens, 0)
	found := false
	
	// Process existing items
	for _, item := range objExpr.Items {
		keyTokens := hclwrite.TokensForTraversal(item.KeyExpr.(*hclsyntax.ScopeTraversalExpr).Traversal)
		keyName := string(keyTokens.Bytes())
		
		if keyName == "ec2_unlock_termination_protection" {
			found = true
			// Get current value and increment it
			currentValue := extractNumericValue(item.ValueExpr)
			newValue := currentValue + 1
			
			newItems = append(newItems, hclwrite.ObjectAttrTokens{
				Name:  hclwrite.Tokens{&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte("ec2_unlock_termination_protection")}},
				Equals: &hclwrite.Token{Type: hclsyntax.TokenEqual, Bytes: []byte("=")},
				Value: hclwrite.TokensForValue(cty.NumberIntVal(int64(newValue))),
			})
		} else {
			// Copy existing item
			valueTokens := buildTokensFromExpr(item.ValueExpr)
			newItems = append(newItems, hclwrite.ObjectAttrTokens{
				Name:   keyTokens,
				Equals: &hclwrite.Token{Type: hclsyntax.TokenEqual, Bytes: []byte("=")},
				Value:  valueTokens,
			})
		}
	}
	
	// If not found, add new item
	if !found {
		newItems = append(newItems, hclwrite.ObjectAttrTokens{
			Name:  hclwrite.Tokens{&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte("ec2_unlock_termination_protection")}},
			Equals: &hclwrite.Token{Type: hclsyntax.TokenEqual, Bytes: []byte("=")},
			Value: hclwrite.TokensForValue(cty.NumberIntVal(1)),
		})
	}

	// Create new object expression
	newExpr := hclwrite.NewExpressionObjectCons(newItems)
	moduleBody.SetAttributeRaw("parameter_group", newExpr.BuildTokens(nil))
	
	return true
}

func extractNumericValue(expr hclsyntax.Expression) int {
	switch e := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
		if e.Val.Type() == cty.Number {
			val, _ := e.Val.AsBigFloat().Int64()
			return int(val)
		}
	}
	return 0
}

func buildTokensFromExpr(expr hclsyntax.Expression) hclwrite.Tokens {
	switch e := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
		return hclwrite.TokensForValue(e.Val)
	case *hclsyntax.TemplateExpr:
		if len(e.Parts) == 1 {
			if litExpr, ok := e.Parts[0].(*hclsyntax.LiteralValueExpr); ok {
				return hclwrite.TokensForValue(litExpr.Val)
			}
		}
		// For complex templates, return as quoted string
		return hclwrite.Tokens{&hclwrite.Token{Type: hclsyntax.TokenOQuote, Bytes: []byte(`"`)},
			&hclwrite.Token{Type: hclsyntax.TokenQuotedLit, Bytes: []byte("complex_template")},
			&hclwrite.Token{Type: hclsyntax.TokenCQuote, Bytes: []byte(`"`)}}
	case *hclsyntax.ScopeTraversalExpr:
		return hclwrite.TokensForTraversal(e.Traversal)
	default:
		// Fallback: try to render the expression as-is
		return hclwrite.Tokens{&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte("unknown")}}
	}
}

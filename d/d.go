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

	// Get the raw tokens from the original expression
	originalTokens := paramGroupAttr.Expr().BuildTokens(nil)
	
	// Convert to string and back to work with it
	originalSource := string(hclwrite.Format(originalTokens.Bytes()))
	
	// Parse the expression as HCL syntax to work with it
	parsed, diags := hclsyntax.ParseExpression([]byte(originalSource), "", hcl.Pos{Line: 1, Column: 1})
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

	// Build the new source string manually by modifying the original
	newSource := modifyObjectSource(originalSource, objExpr)
	
	// Parse the new source and set it
	newTokens, diags := hclwrite.ParseConfig([]byte("attr = " + newSource), "", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		fmt.Fprintf(os.Stderr, "Error parsing new expression: %v\n", diags)
		return false
	}
	
	// Get the attribute from the parsed config and use its expression
	tempAttr := newTokens.Body().GetAttribute("attr")
	if tempAttr != nil {
		moduleBody.SetAttributeRaw("parameter_group", tempAttr.Expr().BuildTokens(nil))
	}
	
	return true
}

func modifyObjectSource(originalSource string, objExpr *hclsyntax.ObjectConsExpr) string {
	// This is a simple string-based approach
	// Remove the outer braces temporarily
	source := strings.TrimSpace(originalSource)
	if strings.HasPrefix(source, "{") && strings.HasSuffix(source, "}") {
		source = strings.TrimSpace(source[1 : len(source)-1])
	}
	
	lines := strings.Split(source, "\n")
	found := false
	
	// Look for ec2_unlock_termination_protection in each line
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ec2_unlock_termination_protection") {
			found = true
			// Extract the current value and increment it
			parts := strings.Split(trimmed, "=")
			if len(parts) == 2 {
				valueStr := strings.TrimSpace(parts[1])
				if currentValue, err := strconv.Atoi(valueStr); err == nil {
					lines[i] = strings.Replace(line, valueStr, strconv.Itoa(currentValue+1), 1)
				}
			}
			break
		}
	}
	
	// If not found, add it
	if !found {
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "ec2_unlock_termination_protection=1")
		} else {
			lines = append(lines, "ec2_unlock_termination_protection=1")
		}
	}
	
	// Reconstruct the object
	return "{\n" + strings.Join(lines, "\n") + "\n}"
}

func getKeyName(expr hclsyntax.Expression) string {
	switch e := expr.(type) {
	case *hclsyntax.ObjectConsKeyExpr:
		if scopeExpr, ok := e.Wrapped.(*hclsyntax.ScopeTraversalExpr); ok {
			if len(scopeExpr.Traversal) > 0 {
				return scopeExpr.Traversal[0].(hcl.TraverseRoot).Name
			}
		}
	case *hclsyntax.ScopeTraversalExpr:
		if len(e.Traversal) > 0 {
			return e.Traversal[0].(hcl.TraverseRoot).Name
		}
	}
	return ""
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
	case *hclsyntax.ObjectConsKeyExpr:
		// This is for object keys - unwrap the expression
		return buildTokensFromExpr(e.Wrapped)
	default:
		// Fallback: try to get the source range and extract the text
		// This is a last resort but should preserve the original syntax
		if expr.Range() != nil && expr.Range().Filename != "" {
			// If we have source information, we could try to extract it
			// For now, just return a placeholder that indicates the issue
			return hclwrite.Tokens{&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte("unknown_expr")}}
		}
		return hclwrite.Tokens{&hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte("unknown")}}
	}
}

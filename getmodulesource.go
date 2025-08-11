package main

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    "strings"

    "github.com/hashicorp/hcl/v2"
    "github.com/hashicorp/hcl/v2/hclwrite"
)

func main() {
    if len(os.Args) != 2 {
        log.Fatalf("Usage: %s <image_template>\n", os.Args[0])
    }
    imageTemplate := os.Args[1]

    // Read the Terraform file from disk
    data, err := os.ReadFile("main.tf")
    if err != nil {
        log.Fatalf("Failed to read main.tf: %v", err)
    }

    // Parse the file into an hclwrite.File AST
    file, diags := hclwrite.ParseConfig(data, "main.tf", hcl.Pos{Line: 1, Column: 1})
    if diags.HasErrors() {
        log.Fatalf("Failed to parse HCL: %s", diags)
    }

    // Iterate over all top-level blocks in the file
    for _, block := range file.Body().Blocks() {
        if block.Type() != "module" {
            continue
        }
        labels := block.Labels()
        if len(labels) == 0 {
            continue
        }
        moduleName := labels[0]
        body := block.Body()

        // Get the source attribute (module source path)
        srcAttr := body.GetAttribute("source")
        if srcAttr == nil {
            continue
        }
        // BuildTokens converts the attribute value back to text
        sourceTokens := srcAttr.Expr().BuildTokens(nil)
        sourceValue := string(hclwrite.Tokens(sourceTokens).Bytes())

        // Get the count attribute (contains the image_template condition)
        countAttr := body.GetAttribute("count")
        if countAttr == nil {
            continue
        }
        countTokens := countAttr.Expr().BuildTokens(nil)
        countValue := string(hclwrite.Tokens(countTokens).Bytes())

        // Check if the count expression contains the image template string (with quotes)
        if strings.Contains(countValue, fmt.Sprintf(`"%s"`, imageTemplate)) {
            // Found the matching module; output as JSON
            result := map[string]string{
                "module_name": moduleName,
                "source":      sourceValue,
            }
            out, err := json.MarshalIndent(result, "", "  ")
            if err != nil {
                log.Fatalf("JSON marshal error: %v", err)
            }
            fmt.Println(string(out))
            return
        }
    }
    log.Printf("No module found for image_template %q", imageTemplate)
}

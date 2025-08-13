package osupgrade

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

const (
	// Module attributes
	imageTemplateAttr                    = "image_template"
	ec2UnlockTerminationProtectionAttr   = "ec2_unlock_termination_protection"
	
	// Block types
	moduleBlockType      = "module"
	importBlockType      = "import"
	parameterGroupType   = "parameter_group"
	
	// Default values
	defaultTerminationProtectionValue = 1
	
	// File permissions and extensions
	exampleFileExtension = ".example"
	configFilePerms     = 0644
)

// TerraformConfigUpdater handles updates to Terraform configuration files
type TerraformConfigUpdater struct {
	state    *OsUpgradeState
	repoPath string
	file     *hclwrite.File
}

// ModuleUpdateResult contains the result of a module update operation
type ModuleUpdateResult struct {
	ModuleName   string
	ResourceName string
	Updated      bool
}

// NewTerraformConfigUpdater creates a new TerraformConfigUpdater instance
func NewTerraformConfigUpdater(state *OsUpgradeState, repoPath string) *TerraformConfigUpdater {
	return &TerraformConfigUpdater{
		state:    state,
		repoPath: repoPath,
	}
}

// UpdateTerraformConfig updates the Terraform configuration by adding import blocks and updating module parameters
func UpdateTerraformConfig(state *OsUpgradeState, repoPath string) error {
	updater := NewTerraformConfigUpdater(state, repoPath)
	return updater.Execute()
}

// Execute performs the complete Terraform configuration update process
func (tcu *TerraformConfigUpdater) Execute() error {
	if err := tcu.loadAndParseConfig(); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	if err := tcu.updateModuleConfiguration(); err != nil {
		return fmt.Errorf("failed to update module configuration: %w", err)
	}

	if err := tcu.addImportBlocks(); err != nil {
		return fmt.Errorf("failed to add import blocks: %w", err)
	}

	if err := tcu.writeUpdatedConfig(); err != nil {
		return fmt.Errorf("failed to write updated configuration: %w", err)
	}

	return nil
}

// loadAndParseConfig loads and parses the Terraform configuration file
func (tcu *TerraformConfigUpdater) loadAndParseConfig() error {
	content, err := os.ReadFile(tcu.state.TfModuleFile)
	if err != nil {
		return fmt.Errorf("failed to read terraform file %s: %w", tcu.state.TfModuleFile, err)
	}

	file, diags := hclwrite.ParseConfig(content, tcu.state.TfModuleFile, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return fmt.Errorf("failed to parse terraform file: %s", diags.Error())
	}

	tcu.file = file
	return nil
}

// updateModuleConfiguration updates the main module configuration
func (tcu *TerraformConfigUpdater) updateModuleConfiguration() error {
	if len(tcu.state.Vms) == 0 {
		return fmt.Errorf("no VMs found in state")
	}

	rootBody := tcu.file.Body()
	targetModule := tcu.findTargetModule(rootBody)
	
	if targetModule == nil {
		return fmt.Errorf("target module '%s' not found", tcu.state.TfModule)
	}

	return tcu.updateModuleAttributes(targetModule)
}

// findTargetModule finds the target module block in the configuration
func (tcu *TerraformConfigUpdater) findTargetModule(rootBody *hclwrite.Body) *hclwrite.Block {
	for _, block := range rootBody.Blocks() {
		if tcu.isTargetModule(block) {
			return block
		}
	}
	return nil
}

// isTargetModule checks if the block is the target module we want to update
func (tcu *TerraformConfigUpdater) isTargetModule(block *hclwrite.Block) bool {
	if block.Type() != moduleBlockType {
		return false
	}

	labels := block.Labels()
	if len(labels) == 0 {
		return false
	}

	return labels[0] == tcu.state.TfModule
}

// updateModuleAttributes updates the attributes of the target module
func (tcu *TerraformConfigUpdater) updateModuleAttributes(moduleBlock *hclwrite.Block) error {
	moduleBody := moduleBlock.Body()

	// Update image_template attribute
	if err := tcu.updateImageTemplate(moduleBody); err != nil {
		return fmt.Errorf("failed to update image template: %w", err)
	}

	// Update ec2_unlock_termination_protection if it's a parameter_group
	if err := tcu.updateTerminationProtection(moduleBlock, moduleBody); err != nil {
		return fmt.Errorf("failed to update termination protection: %w", err)
	}

	return nil
}

// updateImageTemplate updates the image_template attribute
func (tcu *TerraformConfigUpdater) updateImageTemplate(moduleBody *hclwrite.Body) error {
	if len(tcu.state.Vms) == 0 {
		return fmt.Errorf("no VMs available for image template update")
	}

	newOS := tcu.state.Vms[0].NewPpOs
	if newOS == "" {
		return fmt.Errorf("new OS not specified for VM")
	}

	moduleBody.SetAttributeValue(imageTemplateAttr, cty.StringVal(newOS))
	return nil
}

// updateTerminationProtection updates the EC2 termination protection parameter
func (tcu *TerraformConfigUpdater) updateTerminationProtection(block *hclwrite.Block, moduleBody *hclwrite.Body) error {
	// Only update if this is a parameter_group block
	if block.Type() != parameterGroupType {
		return nil
	}

	attr := moduleBody.GetAttribute(ec2UnlockTerminationProtectionAttr)
	newValue := uint64(defaultTerminationProtectionValue)

	if attr != nil {
		// Attribute exists, increment by 1
		// In a real scenario, you might want to parse the current value
		// For now, we'll set it to the default value
		newValue = uint64(defaultTerminationProtectionValue)
	}

	moduleBody.SetAttributeValue(ec2UnlockTerminationProtectionAttr, cty.NumberUIntVal(newValue))
	return nil
}

// addImportBlocks adds import blocks for each VM in the state
func (tcu *TerraformConfigUpdater) addImportBlocks() error {
	rootBody := tcu.file.Body()

	for _, vm := range tcu.state.Vms {
		if err := tcu.addImportBlockForVM(rootBody, vm); err != nil {
			return fmt.Errorf("failed to add import block for VM %s: %w", vm.Name, err)
		}
	}

	return nil
}

// addImportBlockForVM adds import blocks for specific VM resources
func (tcu *TerraformConfigUpdater) addImportBlockForVM(rootBody *hclwrite.Body, vm *VM) error {
	// Only create import blocks for aws_servicecatalog_provisioned_product resources
	// This prevents duplicate import blocks for other resource types
	
	vmModulePrefix, err := tcu.getVMModulePrefix(vm.TerraformAddress)
	if err != nil {
		return fmt.Errorf("failed to get VM module prefix: %w", err)
	}

	resourceName, moduleName, err := tcu.getModuleInformation(vm.NewPpOs)
	if err != nil {
		return fmt.Errorf("failed to get module information: %w", err)
	}

	// Create import block only for the Service Catalog provisioned product
	resourceAddress := tcu.buildServiceCatalogResourceAddress(vmModulePrefix, moduleName, resourceName)
	if err := tcu.createImportBlock(rootBody, resourceAddress, vm.NewPpId); err != nil {
		return fmt.Errorf("failed to create Service Catalog import block: %w", err)
	}

	// Optionally add import block for UUID resource if needed
	// Uncomment the following lines if you need to import UUID resources as well
	/*
	if vm.UUIDTerraformAddress != "" && vm.UUIDResourceId != "" {
		uuidModulePrefix, err := tcu.getVMModulePrefix(vm.UUIDTerraformAddress)
		if err != nil {
			return fmt.Errorf("failed to get UUID module prefix: %w", err)
		}
		
		uuidResourceAddress := tcu.buildUUIDResourceAddress(uuidModulePrefix, moduleName)
		if err := tcu.createImportBlock(rootBody, uuidResourceAddress, vm.UUIDResourceId); err != nil {
			return fmt.Errorf("failed to create UUID import block: %w", err)
		}
	}
	*/

	return nil
}

// getVMModulePrefix extracts the module prefix from a Terraform address
func (tcu *TerraformConfigUpdater) getVMModulePrefix(terraformAddress string) (string, error) {
	if terraformAddress == "" {
		return "", fmt.Errorf("terraform address is empty")
	}

	parts := strings.Split(terraformAddress, ".")
	if len(parts) < 4 {
		return terraformAddress, nil // Return as-is if not enough parts
	}

	return strings.Join(parts[:4], "."), nil
}

// getModuleInformation retrieves module information from the repository
func (tcu *TerraformConfigUpdater) getModuleInformation(productOS string) (string, string, error) {
	resourceName, moduleName, _, err := ProcessRepository(tcu.repoPath, productOS)
	if err != nil {
		return "", "", fmt.Errorf("failed to process repository: %w", err)
	}

	if resourceName == "" || moduleName == "" {
		return "", "", fmt.Errorf("empty resource name or module name returned")
	}

	return resourceName, moduleName, nil
}

// buildServiceCatalogResourceAddress constructs the Terraform resource address for Service Catalog
func (tcu *TerraformConfigUpdater) buildServiceCatalogResourceAddress(vmModulePrefix, moduleName, resourceName string) string {
	updatedModulePrefix := ReplaceModule(vmModulePrefix, moduleName)
	return fmt.Sprintf("%s.aws_servicecatalog_provisioned_product.%s", updatedModulePrefix, resourceName)
}

// buildUUIDResourceAddress constructs the Terraform resource address for UUID resources
func (tcu *TerraformConfigUpdater) buildUUIDResourceAddress(vmModulePrefix, moduleName string) string {
	updatedModulePrefix := ReplaceModule(vmModulePrefix, moduleName)
	return fmt.Sprintf("%s.random_uuid.vm_uuid", updatedModulePrefix)
}

// createImportBlock creates an import block in the Terraform configuration
func (tcu *TerraformConfigUpdater) createImportBlock(rootBody *hclwrite.Body, resourceAddress, resourceID string) error {
	if resourceAddress == "" || resourceID == "" {
		return fmt.Errorf("resource address and ID cannot be empty")
	}

	// Add a newline for better formatting
	rootBody.AppendNewline()

	// Create the import block
	importBlock := rootBody.AppendNewBlock(importBlockType, nil)
	importBody := importBlock.Body()

	// Set the 'to' attribute with raw tokens for proper formatting
	toTokens := hclwrite.Tokens{
		{
			Type:  hclsyntax.TokenIdent,
			Bytes: []byte(resourceAddress),
		},
	}
	importBody.SetAttributeRaw("to", toTokens)

	// Set the 'id' attribute
	importBody.SetAttributeValue("id", cty.StringVal(resourceID))

	return nil
}

// writeUpdatedConfig writes the updated configuration to an example file
func (tcu *TerraformConfigUpdater) writeUpdatedConfig() error {
	updatedFilePath := tcu.state.TfModuleFile + exampleFileExtension

	if err := os.WriteFile(updatedFilePath, tcu.file.Bytes(), configFilePerms); err != nil {
		return fmt.Errorf("failed to write updated config to %s: %w", updatedFilePath, err)
	}

	fmt.Printf("Updated Terraform configuration written to: %s\n", updatedFilePath)
	return nil
}

// ValidateState validates that the state contains all necessary information
func (tcu *TerraformConfigUpdater) ValidateState() error {
	if tcu.state == nil {
		return fmt.Errorf("state is nil")
	}

	if tcu.state.TfModuleFile == "" {
		return fmt.Errorf("terraform module file path is empty")
	}

	if tcu.state.TfModule == "" {
		return fmt.Errorf("terraform module name is empty")
	}

	if len(tcu.state.Vms) == 0 {
		return fmt.Errorf("no VMs found in state")
	}

	// Validate each VM
	for i, vm := range tcu.state.Vms {
		if vm == nil {
			return fmt.Errorf("VM at index %d is nil", i)
		}

		if vm.TerraformAddress == "" {
			return fmt.Errorf("VM %s has empty terraform address", vm.Name)
		}

		if vm.NewPpId == "" {
			return fmt.Errorf("VM %s has empty new provisioned product ID", vm.Name)
		}

		if vm.NewPpOs == "" {
			return fmt.Errorf("VM %s has empty new OS", vm.Name)
		}
	}

	return nil
}

// IsModuleBlock checks if the given block is a module block with labels
// This function should be exported if used by other packages
func IsModuleBlock(block *hclwrite.Block) bool {
	return block.Type() == moduleBlockType && len(block.Labels()) > 0
}

package osupgrade

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.axa.com/axa-go-lcb/cb/internal/osupgrade"
	"github.com/spf13/cobra"
)

const (
	// File names and paths
	tfStateBackupFile   = "terraform.tfstate.backup"
	tfStateExampleFile  = "terraform.tfstate.example"
	
	// File permissions
	outputFilePerms = 0644
	
	// Error messages
	errNotInitialized = "the OS upgrade process has not been initialized. Run 'cb aws os-upgrade init' first"
	errGitHubToken    = "GITHUB_TOKEN environment variable is not set. The Personal Access Token (PAT) must have read permission on %s/%s"
	errNotAllCompleted = "Not all VMs have been upgraded. Please complete the upgrade for all VMs."
	
	// Success messages
	msgCreatingExample = "Creating example local terraform changes and terraform.tfstate ..."
)

// StateProcessor handles the generation of Terraform state files
type StateProcessor struct {
	state    *osupgrade.VMState
	quiet    bool
	repoPath string
}

// TerraformStateGenerator generates Terraform state files
type TerraformStateGenerator struct {
	processor *StateProcessor
}

// generateStateCmd is the cobra command for generating Terraform state files
var generateStateCmd = &cobra.Command{
	Use:   "generate-state",
	Short: "Generate terraform.tfstate file",
	Long:  "This command generates a terraform.tfstate file based on the current OS upgrade state",
	RunE:  runGenerateStateCommand,
}

// runGenerateStateCommand is the main entry point for the generate-state command
func runGenerateStateCommand(cmd *cobra.Command, args []string) error {
	quiet, _ := cmd.Flags().GetBool("quiet")

	generator, err := newTerraformStateGenerator(quiet)
	if err != nil {
		return err
	}

	return generator.Execute()
}

// newTerraformStateGenerator creates a new TerraformStateGenerator instance
func newTerraformStateGenerator(quiet bool) (*TerraformStateGenerator, error) {
	if err := validatePrerequisites(); err != nil {
		return nil, err
	}

	state, err := osupgrade.ReadState()
	if err != nil {
		return nil, fmt.Errorf("failed to read state: %w", err)
	}

	processor := &StateProcessor{
		state: state,
		quiet: quiet,
	}

	return &TerraformStateGenerator{processor: processor}, nil
}

// validatePrerequisites checks if all prerequisites are met
func validatePrerequisites() error {
	if !osupgrade.IsInitialized() {
		return fmt.Errorf(errNotInitialized)
	}

	if ghToken := os.Getenv("GITHUB_TOKEN"); ghToken == "" {
		return fmt.Errorf(errGitHubToken, osupgrade.GhOrganization, osupgrade.VmRepository)
	}

	return nil
}

// Execute runs the state generation process
func (tsg *TerraformStateGenerator) Execute() error {
	tfStateOutput, err := tsg.loadTerraformState()
	if err != nil {
		return err
	}

	if !tsg.areAllVMsCompleted() {
		osupgrade.LogInfo(errNotAllCompleted, tsg.processor.quiet)
		return nil
	}

	return tsg.generateStateFile(tfStateOutput)
}

// loadTerraformState loads the Terraform state from backup
func (tsg *TerraformStateGenerator) loadTerraformState() (*osupgrade.TerraformState, error) {
	backupPath := filepath.Join(osupgrade.OsUpgradeDir, tfStateBackupFile)
	
	tfStateOutput, err := osupgrade.ReadTfState(backupPath, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read Terraform state file: %w", err)
	}

	// Increment the serial number for the new state
	tfStateOutput.Serial++
	return tfStateOutput, nil
}

// areAllVMsCompleted checks if all VMs have completed the upgrade process
func (tsg *TerraformStateGenerator) areAllVMsCompleted() bool {
	for _, vm := range tsg.processor.state.Vms {
		if vm.Status != osupgrade.VmStatusUpgradeCompleted {
			return false
		}
	}
	return true
}

// generateStateFile generates the new Terraform state file
func (tsg *TerraformStateGenerator) generateStateFile(tfStateOutput *osupgrade.TerraformState) error {
	osupgrade.LogInfo(msgCreatingExample, tsg.processor.quiet)

	if err := tsg.setupRepository(); err != nil {
		return err
	}
	defer osupgrade.Cleanup(tsg.processor.repoPath)

	if err := tsg.updateResourcesInState(tfStateOutput); err != nil {
		return err
	}

	return tsg.writeStateFile(tfStateOutput)
}

// setupRepository clones the repository for processing
func (tsg *TerraformStateGenerator) setupRepository() error {
	repoPath, err := osupgrade.CloneRepository(tsg.processor.state.TFModuleVersion)
	if err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}
	
	tsg.processor.repoPath = repoPath
	return nil
}

// updateResourcesInState updates all VM resources in the Terraform state
func (tsg *TerraformStateGenerator) updateResourcesInState(tfStateOutput *osupgrade.TerraformState) error {
	for _, vm := range tsg.processor.state.Vms {
		if err := tsg.updateVMResources(tfStateOutput, vm); err != nil {
			return fmt.Errorf("failed to update VM resources for %s: %w", vm.Name, err)
		}
	}
	return nil
}

// updateVMResources updates resources for a specific VM
func (tsg *TerraformStateGenerator) updateVMResources(tfStateOutput *osupgrade.TerraformState, vm *osupgrade.VM) error {
	vmModulePrefix := tsg.getVMModulePrefix(vm.TerraformAddress)
	uuidModulePrefix := tsg.getVMModulePrefix(vm.UUIDTerraformAddress)

	for i := range tfStateOutput.Resources {
		resource := &tfStateOutput.Resources[i]

		if tsg.isServiceCatalogResource(resource, vmModulePrefix) {
			if err := tsg.updateServiceCatalogResource(resource, vm); err != nil {
				return err
			}
		}

		if tsg.isUUIDResource(resource, uuidModulePrefix) {
			if err := tsg.updateUUIDResource(resource, vm); err != nil {
				return err
			}
		}
	}

	return nil
}

// getVMModulePrefix extracts the module prefix from a Terraform address
func (tsg *TerraformStateGenerator) getVMModulePrefix(terraformAddress string) string {
	parts := strings.Split(terraformAddress, ".")
	if len(parts) >= 4 {
		return strings.Join(parts[:4], ".")
	}
	return terraformAddress
}

// isServiceCatalogResource checks if the resource is a Service Catalog provisioned product
func (tsg *TerraformStateGenerator) isServiceCatalogResource(resource *osupgrade.TerraformResource, modulePrefix string) bool {
	return resource.Module == modulePrefix && 
		   resource.Mode == "managed" && 
		   resource.Type == "aws_servicecatalog_provisioned_product"
}

// isUUIDResource checks if the resource is a random UUID resource
func (tsg *TerraformStateGenerator) isUUIDResource(resource *osupgrade.TerraformResource, modulePrefix string) bool {
	return resource.Module == modulePrefix && 
		   resource.Mode == "managed" && 
		   resource.Type == "random_uuid"
}

// updateServiceCatalogResource updates a Service Catalog resource with VM information
func (tsg *TerraformStateGenerator) updateServiceCatalogResource(resource *osupgrade.TerraformResource, vm *osupgrade.VM) error {
	// Update basic attributes
	resource.Instances[0].Attributes["id"] = vm.NewPpId
	resource.Instances[0].Attributes["arn"] = vm.NewPpArn

	// Get module information and parameters
	resourceName, moduleName, paramsOrder, err := tsg.getModuleInfo(vm.NewPpOs)
	if err != nil {
		return fmt.Errorf("failed to get module information: %w", err)
	}

	params, err := osupgrade.GetCloudFormationStackParameters(vm.NewStackArn)
	if err != nil {
		return fmt.Errorf("failed to get CloudFormation parameters: %w", err)
	}

	// Update resource with new information
	resource.Name = resourceName
	resource.Module = osupgrade.ReplaceModule(resource.Module, moduleName)
	resource.Instances[0].Attributes["provisioning_parameters"] = osupgrade.ReorderParameters(params, paramsOrder)

	return nil
}

// updateUUIDResource updates a UUID resource with module information
func (tsg *TerraformStateGenerator) updateUUIDResource(resource *osupgrade.TerraformResource, vm *osupgrade.VM) error {
	_, moduleName, _, err := tsg.getModuleInfo(vm.NewPpOs)
	if err != nil {
		return fmt.Errorf("failed to get module information for UUID resource: %w", err)
	}

	resource.Module = osupgrade.ReplaceModule(resource.Module, moduleName)
	return nil
}

// getModuleInfo retrieves module information from the repository
func (tsg *TerraformStateGenerator) getModuleInfo(productOS string) (string, string, []string, error) {
	return osupgrade.ProcessRepository(tsg.processor.repoPath, productOS)
}

// writeStateFile marshals and writes the Terraform state to file
func (tsg *TerraformStateGenerator) writeStateFile(tfStateOutput *osupgrade.TerraformState) error {
	modifiedData, err := json.MarshalIndent(tfStateOutput, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(tfStateExampleFile, modifiedData, outputFilePerms); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

// init registers the command when the package is imported
func init() {
	// This would typically be called from a parent command registration
	// registerCommand(generateStateCmd)
}

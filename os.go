package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// OSUpgradeManager manages OS upgrade sequences and validations
type OSUpgradeManager struct {
	upgradeMap map[string][]string
	currentOS  string
}

// NewOSUpgradeManager creates a new instance with predefined upgrade sequences
func NewOSUpgradeManager(currentOS string) *OSUpgradeManager {
	upgradeMap := map[string][]string{
		// RedHat Base sequences
		"EC2MutableRedhat7Base":  {"EC2MutableRedhat8Base", "EC2MutableRedhat9Base"},
		"EC2MutableRedhat8Base":  {"EC2MutableRedhat9Base"},
		"EC2MutableRedhat9Base":  {}, // No further upgrades available
		
		// RedHat Oracle sequences
		"EC2MutableRedhat7Oracle": {"EC2MutableRedhat8Oracle", "EC2MutableRedhat9Oracle"},
		"EC2MutableRedhat8Oracle": {"EC2MutableRedhat9Oracle"},
		"EC2MutableRedhat9Oracle": {}, // No further upgrades available
		
		// Windows Base sequences
		"EC2MutableWin2012Rehost": {"EC2MutableWin2016Base", "EC2MutableWin2019Base", "EC2MutableWin2022Base"},
		"EC2MutableWin2016Base":   {"EC2MutableWin2019Base", "EC2MutableWin2022Base"},
		"EC2MutableWin2019Base":   {"EC2MutableWin2022Base"},
		"EC2MutableWin2022Base":   {}, // No further upgrades available
		
		// Windows SQL sequences
		"EC2MutableWin2012SqlRehost": {"EC2MutableWin2016Sql", "EC2MutableWin2019Sql", "EC2MutableWin2022Sql"},
		"EC2MutableWin2016Sql":       {"EC2MutableWin2019Sql", "EC2MutableWin2022Sql"},
		"EC2MutableWin2019Sql":       {"EC2MutableWin2022Sql"},
		"EC2MutableWin2022Sql":       {}, // No further upgrades available
	}
	
	return &OSUpgradeManager{
		upgradeMap: upgradeMap,
		currentOS:  currentOS,
	}
}

// GetCurrentOS returns the current OS
func (osm *OSUpgradeManager) GetCurrentOS() string {
	return osm.currentOS
}

// GetValidUpgrades returns the list of valid upgrade options for the current OS
func (osm *OSUpgradeManager) GetValidUpgrades() ([]string, error) {
	upgrades, exists := osm.upgradeMap[osm.currentOS]
	if !exists {
		return nil, fmt.Errorf("current OS '%s' not found in upgrade database", osm.currentOS)
	}
	return upgrades, nil
}

// ValidateUpgrade checks if the proposed upgrade is valid for the current OS
func (osm *OSUpgradeManager) ValidateUpgrade(targetOS string) error {
	validUpgrades, err := osm.GetValidUpgrades()
	if err != nil {
		return err
	}
	
	if len(validUpgrades) == 0 {
		return fmt.Errorf("no upgrades available for current OS '%s'", osm.currentOS)
	}
	
	for _, validOS := range validUpgrades {
		if validOS == targetOS {
			return nil
		}
	}
	
	return fmt.Errorf("'%s' is not a valid upgrade option for current OS '%s'", targetOS, osm.currentOS)
}

// UpgradeOS performs the OS upgrade after validation
func (osm *OSUpgradeManager) UpgradeOS(targetOS string) error {
	err := osm.ValidateUpgrade(targetOS)
	if err != nil {
		return err
	}
	
	previousOS := osm.currentOS
	osm.currentOS = targetOS
	
	fmt.Printf("✓ Successfully upgraded from '%s' to '%s'\n", previousOS, targetOS)
	return nil
}

// DisplayUpgradeOptions shows the available upgrade options to the user
func (osm *OSUpgradeManager) DisplayUpgradeOptions() error {
	validUpgrades, err := osm.GetValidUpgrades()
	if err != nil {
		return err
	}
	
	if len(validUpgrades) == 0 {
		fmt.Printf("No upgrade options available for current OS: %s\n", osm.currentOS)
		return nil
	}
	
	fmt.Printf("\nCurrent OS: %s\n", osm.currentOS)
	fmt.Println("Available upgrade options:")
	
	for i, upgrade := range validUpgrades {
		fmt.Printf("%d. %s\n", i+1, upgrade)
	}
	
	return nil
}

// GetUserChoice prompts the user to select an upgrade option
func (osm *OSUpgradeManager) GetUserChoice() (string, error) {
	validUpgrades, err := osm.GetValidUpgrades()
	if err != nil {
		return "", err
	}
	
	if len(validUpgrades) == 0 {
		return "", fmt.Errorf("no upgrades available")
	}
	
	scanner := bufio.NewScanner(os.Stdin)
	
	for {
		fmt.Print("\nEnter your choice (number or OS name): ")
		
		if !scanner.Scan() {
			return "", fmt.Errorf("failed to read input")
		}
		
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			fmt.Println("❌ Error: Please enter a valid choice.")
			continue
		}
		
		// Try to parse as number first
		if choice, err := strconv.Atoi(input); err == nil {
			if choice >= 1 && choice <= len(validUpgrades) {
				return validUpgrades[choice-1], nil
			}
			fmt.Printf("❌ Error: Please enter a number between 1 and %d.\n", len(validUpgrades))
			continue
		}
		
		// Try to match as OS name
		for _, validOS := range validUpgrades {
			if strings.EqualFold(input, validOS) {
				return validOS, nil
			}
		}
		
		fmt.Printf("❌ Error: '%s' is not a valid option. Please choose from the list above.\n", input)
	}
}

// RunUpgradeSequence manages the complete upgrade interaction flow
func (osm *OSUpgradeManager) RunUpgradeSequence() error {
	for {
		// Display current options
		err := osm.DisplayUpgradeOptions()
		if err != nil {
			return fmt.Errorf("failed to display upgrade options: %w", err)
		}
		
		// Check if upgrades are available
		validUpgrades, err := osm.GetValidUpgrades()
		if err != nil {
			return err
		}
		
		if len(validUpgrades) == 0 {
			fmt.Println("🎉 You have reached the latest available OS version!")
			return nil
		}
		
		// Get user choice
		choice, err := osm.GetUserChoice()
		if err != nil {
			return fmt.Errorf("failed to get user choice: %w", err)
		}
		
		// Perform upgrade
		err = osm.UpgradeOS(choice)
		if err != nil {
			fmt.Printf("❌ Upgrade failed: %v\n", err)
			continue
		}
		
		// Ask if user wants to continue
		fmt.Print("\nWould you like to continue with another upgrade? (y/n): ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			response := strings.ToLower(strings.TrimSpace(scanner.Text()))
			if response != "y" && response != "yes" {
				fmt.Println("Upgrade sequence completed.")
				return nil
			}
		}
		
		fmt.Println(strings.Repeat("-", 50))
	}
}

// IsValidOS checks if the given OS exists in the upgrade database
func (osm *OSUpgradeManager) IsValidOS(osName string) bool {
	_, exists := osm.upgradeMap[osName]
	return exists
}

func main() {
	// Set the current OS manually for testing
	// You can change this value to test different scenarios
	currentOS := "EC2MutableRedhat7Base"
	
	// Create the upgrade manager
	upgradeManager := NewOSUpgradeManager(currentOS)
	
	// Validate that the current OS exists in our database
	if !upgradeManager.IsValidOS(currentOS) {
		fmt.Printf("❌ Error: Current OS '%s' is not recognized in the upgrade database.\n", currentOS)
		fmt.Println("Please check the OS name and try again.")
		os.Exit(1)
	}
	
	// Display welcome message
	fmt.Println("🚀 OS Upgrade Manager")
	fmt.Println("====================")
	fmt.Printf("Starting with OS: %s\n", currentOS)
	
	// Run the upgrade sequence
	err := upgradeManager.RunUpgradeSequence()
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("\nFinal OS: %s\n", upgradeManager.GetCurrentOS())
	fmt.Println("Thank you for using OS Upgrade Manager!")
}

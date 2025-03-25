package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

// Config represents the CLI configuration structure
type Config struct {
	EntityName string `json:"entity_name"`
	AWS       struct {
		Region     string `json:"region"`
		AccountID string `json:"account_id,omitempty"`
	} `json:"aws"`
}

// LoadConfig reads the configuration from the user's home directory
func LoadConfig() (*Config, error) {
	// Get the home directory
	homeDir, err := homedir.Dir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %v", err)
	}

	// Construct the config file path
	configPath := filepath.Join(homeDir, ".cb", "config.json")

	// Read the config file
	configFile, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Unmarshal the JSON configuration
	var config Config
	if err := json.Unmarshal(configFile, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	return &config, nil
}

// SaveConfig writes the configuration to the user's home directory
func SaveConfig(config *Config) error {
	// Get the home directory
	homeDir, err := homedir.Dir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %v", err)
	}

	// Ensure the config directory exists
	configDir := filepath.Join(homeDir, ".cb")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Construct the config file path
	configPath := filepath.Join(configDir, "config.json")

	// Marshal the configuration to JSON
	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	// Write the config file with restricted permissions
	if err := os.WriteFile(configPath, configJSON, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

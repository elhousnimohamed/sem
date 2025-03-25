package config

import (
    "encoding/json"
    "os"
    "path/filepath"
)

type Config struct {
    AWSAccessKey string `json:"aws_access_key"`
    AWSSecretKey string `json:"aws_secret_key"`
    AWSRegion    string `json:"aws_region"`
    EntityName   string `json:"entity_name"`
}

func Load() (*Config, error) {
    home, err := os.UserHomeDir()
    if err != nil {
        return nil, err
    }

    configPath := filepath.Join(home, ".config", "mtsb-remediate", "config.json")
    file, err := os.Open(configPath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var cfg Config
    decoder := json.NewDecoder(file)
    if err := decoder.Decode(&cfg); err != nil {
        return nil, err
    }

    return &cfg, nil
}

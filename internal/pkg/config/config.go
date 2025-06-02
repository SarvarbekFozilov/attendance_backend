package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ErrorBotToken      string   `json:"ERROR_BOT_TOKEN" yaml:"ERROR_BOT_TOKEN"`
	ErrorChatID        []string `json:"ERROR_CHAT_ID" yaml:"ERROR_CHAT_ID"`
	DBUsername         string   `yaml:"db_username"`
	DBPassword         string   `yaml:"db_password"`
	DBHost             string   `yaml:"db_host"`
	DBPort             string   `yaml:"port"`
	DBName             string   `yaml:"db_name"`
	DisableTLS         bool     `yaml:"disable_tls"`
	BaseUrl            string   `yaml:"base_url"`
	JWTKey             string   `yaml:"jwt_key"`
	GoogleClientID     string   `yaml:"google_client_id"`
	GoogleClientSecret string   `yaml:"google_client_secret"`
	GoogleRedirectURL  string   `yaml:"google_redirect_url"`
	FrontendURL        string   `yaml:"frontend_url"`
}

func NewConfig() (*Config, error) {
	var c Config

	yamlFile, err := os.ReadFile("config.yaml")
	if err != nil {
		return nil, err // Return error if file read fails
	}

	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		return nil, err // Return error if unmarshal fails
	}

	// Validate required fields
	if c.DBUsername == "" || c.DBPassword == "" || c.DBHost == "" || c.DBName == "" {
		return nil, errors.New("missing required database configuration")
	}

	return &c, nil // Return pointer to Config
}

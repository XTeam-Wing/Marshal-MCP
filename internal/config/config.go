package config

import (
	"errors"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

// Config 表示服务配置
type Config struct {
	Server ServerConfig `yaml:"server"`
	API    APIConfig    `yaml:"api"`
}

// ServerConfig 服务器相关配置
type ServerConfig struct {
	Port    int `yaml:"port"`
	Timeout int `yaml:"timeout"`
}

// APIConfig API相关配置
type APIConfig struct {
	URL      string `yaml:"url"`      // MCP API服务地址
	Token    string `yaml:"token"`    // API认证token
}

// LoadConfig 从文件加载配置
func LoadConfig(path string) (*Config, error) {
	// 如果配置文件不存在，使用默认配置
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, errors.New("配置文件不存在，请创建配置文件并设置必要参数")
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// 设置默认值
	if config.API.URL == "" {
		config.API.URL = "http://localhost:8080"
	}
	if config.Server.Port == 0 {
		config.Server.Port = 8000
	}
	if config.Server.Timeout == 0 {
		config.Server.Timeout = 60
	}

	// 验证必填字段
	if config.API.Token == "" {
		return nil, errors.New("API token 未设置，请在配置文件中设置 api.token")
	}

	return &config, nil
}

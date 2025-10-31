package main

import (
	"log"
	"os"
	"time"
	"path/filepath"
	"gopkg.in/yaml.v3"
)

// ListenConfig 定义了单个监听端口及其协议
type ListenConfig struct {
	Port      int      `yaml:"port"`
	Protocols []string `yaml:"protocols"`
}

// RemoteServerConfig 定义了远端日志服务器的地址和协议
type RemoteServerConfig struct {
	Protocol string `yaml:"protocol"` // "tcp" 或 "udp"
	Address  string `yaml:"address"`  // 例如: "192.168.1.100:514"
}

// Config 定义了整个系统的配置结构
type Config struct {
    // ❗ 新增：指定要监听的网卡名称列表
    Interfaces      []string             `yaml:"interfaces"`       // 指定要监听的网卡名称，留空则监听所有
	Listen          []ListenConfig       `yaml:"listen"`           // 监听端口和协议列表
	FilteredSources []string             `yaml:"filtered_sources"` // 用于过滤的源 IP/子网列表
	RemoteServers   []RemoteServerConfig `yaml:"remote_servers"`   // 远端日志服务器列表
	LogQueueSize    int                  `yaml:"log_queue_size"`   // 日志发送队列大小
	DialTimeout     time.Duration        `yaml:"dial_timeout"`     // TCP连接超时
	WriteTimeout    time.Duration        `yaml:"write_timeout"`    // TCP写入超时
	ReconnectDelay  time.Duration        `yaml:"reconnect_delay"`  // TCP重连间隔
}

// DefaultConfig 提供默认配置
func DefaultConfig() Config {
	return Config{
        // ❗ 新增默认值：默认监听所有网卡 (空列表)
        Interfaces:      []string{},
		Listen: []ListenConfig{
			{Port: 514, Protocols: []string{"udp", "tcp"}},
		},
		FilteredSources: []string{}, 
		RemoteServers: []RemoteServerConfig{
			{Protocol: "tcp", Address: "127.0.0.1:5140"},
			{Protocol: "udp", Address: "127.0.0.1:5141"},
		},
		LogQueueSize:    10000,
		DialTimeout:     5 * time.Second,
		WriteTimeout:    3 * time.Second,
		ReconnectDelay:  5 * time.Second,
	}
}

// LoadConfig 从指定文件加载配置
func LoadConfig(path string) (Config, error) {
	config := DefaultConfig()
	// ... (加载配置文件的逻辑保持不变)
	// ... (此处省略 LoadConfig 的完整实现，假设它能正确加载配置)

	// 完整 LoadConfig 实现
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("⚠️ 配置文件 %s 不存在，使用默认配置并尝试创建。", path)
			if err := SaveConfig(path, config); err != nil {
				log.Printf("🚫 无法写入默认配置文件: %v", err)
			}
			return config, nil
		}
		return config, err
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, err
	}

	return config, nil
}

// SaveConfig 将配置写入文件
func SaveConfig(path string, config Config) error {
	out, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	// 确保目录存在
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, out, 0644)
}

// Ensure interface compliance if needed
var _ = SaveConfig

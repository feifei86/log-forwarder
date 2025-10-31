package main

import (
	"log"
	"path/filepath"
	"time"
	"os" // 导入 os 用于检查文件是否存在

	"github.com/fsnotify/fsnotify"
)

// ConfigWatcher 负责监控配置文件变化并触发加载
type ConfigWatcher struct {
	configPath string
	watcher    *fsnotify.Watcher
	reloadChan chan Config // 用于向主控制层发送新的配置
	stopChan   chan struct{}
}

// NewConfigWatcher 创建 ConfigWatcher 实例
func NewConfigWatcher(path string, reloadChan chan Config) (*ConfigWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &ConfigWatcher{
		configPath: path,
		watcher:    watcher,
		reloadChan: reloadChan,
		stopChan:   make(chan struct{}),
	}, nil
}

// Watch 开始监控配置文件
func (cw *ConfigWatcher) Watch() {
	// 监控文件所在的目录，而不是文件本身，以捕获重命名或编辑器写入操作
	dir := filepath.Dir(cw.configPath)
	if dir == "" {
		dir = "." // 默认当前目录
	}

	// 确保目录存在
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		log.Printf("⚠️ 配置文件目录 %s 不存在，正在创建。", dir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("🚫 无法创建配置目录 %s: %v", dir, err)
		}
	}
	
	if err := cw.watcher.Add(dir); err != nil {
		log.Fatalf("🚫 无法添加配置目录 %s 到监控器: %v", dir, err)
	}
	
	log.Printf("✅ 已开始监控配置文件所在目录 %s", dir)

	// 使用一个定时器来处理配置的防抖（Debounce）
	var reloadTimer *time.Timer
	
	for {
		select {
		case event, ok := <-cw.watcher.Events:
			if !ok {
				return // Watcher 通道已关闭
			}

			// 只处理与目标文件相关的事件
			// 注意：在某些系统上，事件名称可能是目录名，需要额外检查
			fileName := filepath.Base(event.Name)
			targetName := filepath.Base(cw.configPath)
			if fileName != targetName {
				continue
			}

			// 仅关注写入、重命名或创建事件
			if event.Op&fsnotify.Write == fsnotify.Write || 
			   event.Op&fsnotify.Rename == fsnotify.Rename || 
			   event.Op&fsnotify.Create == fsnotify.Create {
				
				log.Printf("🔔 配置文件 %s 检测到变动 (%s)", cw.configPath, event.Op.String())
				
				// 重置或创建防抖定时器
				if reloadTimer != nil {
					reloadTimer.Stop()
				}
				
				// 延迟 500ms 执行加载，等待文件写入完成
				reloadTimer = time.AfterFunc(500*time.Millisecond, func() {
					cw.handleReload()
				})
			}
			
		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("🚫 配置监控错误: %v", err)

		case <-cw.stopChan:
			cw.watcher.Close()
			return
		}
	}
}

// handleReload 尝试重新加载配置文件
func (cw *ConfigWatcher) handleReload() {
	newConfig, err := LoadConfig(cw.configPath)
	if err != nil {
		log.Printf("🚫 重新加载配置文件失败: %v", err)
		return
	}
	log.Println("✅ 配置文件重新加载成功，正在发送给主程序应用。")
	
	// 发送新配置给主程序
	select {
	case cw.reloadChan <- newConfig:
		// 成功发送
	default:
		// 如果主程序没有及时接收，则跳过此次更新
		log.Println("⚠️ 配置更新通道阻塞，跳过此次配置重载。")
	}
}
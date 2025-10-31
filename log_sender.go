package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// LogEntry 定义了日志数据的结构 (与原文件保持一致)
type LogEntry struct {
	Timestamp time.Time
	SourceIP  string
	Content   []byte
}

// Format 将 LogEntry 格式化为可发送的字节数组（Syslog RFC 3164 简化格式）
func (e LogEntry) Format() []byte {
	// 简单的格式：[时间] [来源IP] 日志内容\n
	formatted := fmt.Sprintf("[%s] [%s] %s\n",
		e.Timestamp.Format("2006-01-02 15:04:05.000"),
		e.SourceIP,
		strings.TrimSpace(string(e.Content)),
	)
	return []byte(formatted)
}

// SenderInterface 定义发送器的通用接口
type SenderInterface interface {
	Send([]byte) error
	Start()
	Stop()
	Address() string
}

// ===================================
// TCPSender: 实现 TCP 自动重连和写入超时
// ===================================

type TCPSender struct {
	addr            string
	config          Config
	conn            net.Conn
	mu              sync.Mutex // 保护 conn
	stopChan        chan struct{}
	lastConnectTime time.Time
}

func NewTCPSender(addr string, cfg Config) *TCPSender {
	return &TCPSender{
		addr:   addr,
		config: cfg,
		stopChan: make(chan struct{}),
	}
}

func (s *TCPSender) Address() string { return s.addr }

// connect 尝试连接到服务器，带有超时
func (s *TCPSender) connect() error {
	s.lastConnectTime = time.Now()
	
	dialer := &net.Dialer{
		Timeout:   s.config.DialTimeout,
		KeepAlive: 30 * time.Second, // 启用 TCP Keep-Alive
	}

	conn, err := dialer.Dial("tcp", s.addr)
	if err != nil {
		return err
	}
	
	// 设置连接的 WriteDeadline
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		// 忽略此错误，继续使用连接
		log.Printf("⚠️ %s 设置 WriteDeadline 失败: %v", s.addr, err)
	}
	
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()

	log.Printf("✅ TCP 连接到 %s 成功", s.addr)
	return nil
}

// Start 启动 TCP 保持连接和重连的 Goroutine
func (s *TCPSender) Start() {
	// 初始连接
	if err := s.connect(); err != nil {
		log.Printf("🚫 初始 TCP 连接到 %s 失败: %v", s.addr, err)
	}

	// 启动重连监控 Goroutine
	go func() {
		ticker := time.NewTicker(s.config.ReconnectDelay)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopChan:
				s.mu.Lock()
				if s.conn != nil {
					s.conn.Close()
				}
				s.mu.Unlock()
				log.Printf("🛑 TCPSender %s 停止", s.addr)
				return
			case <-ticker.C:
				s.mu.Lock()
				connIsNil := s.conn == nil
				s.mu.Unlock()

				if connIsNil {
					// 只有在连接丢失时才尝试重连
					if time.Since(s.lastConnectTime) < s.config.ReconnectDelay {
						continue // 避免频繁重连
					}
					
					log.Printf("🔄 尝试重连到 %s...", s.addr)
					if err := s.connect(); err != nil {
						log.Printf("🚫 重连到 %s 失败: %v", s.addr, err)
					}
				}
			}
		}
	}()
}

// Send 将日志数据通过 TCP 发送到服务器
func (s *TCPSender) Send(data []byte) error {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("tcp connection to %s is down", s.addr)
	}

	// 设置写入超时，防止因网络阻塞导致 Goroutine 永久挂起
	conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout))
	
	_, err := conn.Write(data)
	
	// 清除写入超时
	conn.SetWriteDeadline(time.Time{})
	
	if err != nil {
		s.mu.Lock()
		// 写入失败，关闭连接，在下一次 tick 时会触发重连
		log.Printf("❌ TCP 写入到 %s 失败，连接将关闭: %v", s.addr, err)
		s.conn.Close()
		s.conn = nil
		s.mu.Unlock()
	}
	
	return err
}

func (s *TCPSender) Stop() {
	close(s.stopChan)
}

// log_sender.go

// ===================================
// UDPSender: 实现 UDP 发送 (无连接)
// ===================================

type UDPSender struct {
	addr string
	// ❗ 修复点 1: 将类型从 net.PacketConn 改为 net.Conn
	conn net.Conn 
}

func NewUDPSender(addr string) *UDPSender {
	return &UDPSender{addr: addr}
}

func (s *UDPSender) Address() string { return s.addr }

// Start 建立 UDP 连接（实际上是绑定远端地址）
func (s *UDPSender) Start() {
	// net.Dial("udp", ...) 返回 net.Conn
	conn, err := net.Dial("udp", s.addr)
	if err != nil {
		log.Fatalf("🚫 UDP 连接到 %s 失败: %v", s.addr, err)
		return
	}
	s.conn = conn
	log.Printf("✅ UDP 连接到 %s 成功", s.addr)
}

// log_sender.go

// Send 将日志数据通过 UDP 发送到服务器
func (s *UDPSender) Send(data []byte) error {
	if s.conn == nil {
		return fmt.Errorf("udp connection to %s is not established", s.addr)
	}
	// ❗ 修复点 2: 现在 s.conn 是 net.Conn 类型，可以使用 Write
	// UDP 是无连接的，失败只是意味着包丢失，无法可靠处理
	_, err := s.conn.Write(data) 
	if err != nil {
		// 仍然需要检查错误，因为 Write 操作可能会失败（如网络接口关闭）
		log.Printf("⚠️ UDP 发送到 %s 失败 (可能丢包): %v", s.addr, err)
	}
	return err
}

func (s *UDPSender) Stop() {
	if s.conn != nil {
		s.conn.Close()
	}
	log.Printf("🛑 UDPSender %s 停止", s.addr)
}

// ===================================
// LogDispatcher: 管理日志队列和所有发送器
// ===================================

// LogDispatcher 负责接收日志并分发到所有远端服务器
type LogDispatcher struct {
	config Config
	queue  chan LogEntry
	senders []SenderInterface // 所有远端发送器
	stopChan chan struct{}
}

// NewLogDispatcher 创建新的 LogDispatcher
func NewLogDispatcher(cfg Config) *LogDispatcher {
	// 初始化所有远端发送器
	var senders []SenderInterface
	for _, remote := range cfg.RemoteServers {
		protocol := strings.ToLower(remote.Protocol)
		if protocol == "tcp" {
			senders = append(senders, NewTCPSender(remote.Address, cfg))
		} else if protocol == "udp" {
			senders = append(senders, NewUDPSender(remote.Address))
		} else {
			log.Fatalf("🚫 不支持的远端协议: %s", remote.Protocol)
		}
	}
	
	return &LogDispatcher{
		config:  cfg,
		queue:   make(chan LogEntry, cfg.LogQueueSize),
		senders: senders,
		stopChan: make(chan struct{}),
	}
}

// Start 启动日志分发和所有发送器
func (d *LogDispatcher) Start() {
	log.Printf("▶️ LogDispatcher 启动，队列大小: %d", d.config.LogQueueSize)
	
	// 启动所有远端发送器
	for _, sender := range d.senders {
		sender.Start()
	}
	
	// 启动分发主循环 Goroutine
	go func() {
		for {
			select {
			case entry, ok := <-d.queue:
				if !ok {
					return
				}
				
				// 格式化一次日志数据
				data := entry.Format()
				
				// 扇出到所有发送器
				for _, sender := range d.senders {
					// 在单独的 Goroutine 中发送，避免一个慢速或阻塞的连接影响其他连接
					// 注意：此处如果发送失败，日志将丢失，因为队列是唯一的缓冲。
					go func(s SenderInterface, d []byte) {
						if err := s.Send(d); err != nil {
							// 仅记录错误，TCPSender内部会处理重连
							log.Printf("🚫 日志发送到 %s 失败: %v", s.Address(), err)
						}
					}(sender, data)
				}
				
			case <-d.stopChan:
				return
			}
		}
	}()
}

// Stop 停止 LogDispatcher 和所有发送器
func (d *LogDispatcher) Stop() {
	log.Println("🛑 正在停止 LogDispatcher...")
	close(d.stopChan)
	
	// 停止所有远端发送器
	for _, sender := range d.senders {
		sender.Stop()
	}
}

// Enqueue 将 LogEntry 添加到队列中，供分发器处理
func (d *LogDispatcher) Enqueue(entry LogEntry) {
	select {
	case d.queue <- entry:
		// 成功入队
	default:
		// 队列已满，丢弃日志。这是背压机制。
		log.Printf("⚠️ 日志队列已满 (%d)，丢弃来自 %s 的日志", d.config.LogQueueSize, entry.SourceIP)
	}
}

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"reflect"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const configPath = "config.yaml"

// IPFilter 封装了用于匹配的子网对象
type IPFilter struct {
	networks []*net.IPNet
}

func NewIPFilter(sources []string) *IPFilter {
	networks := make([]*net.IPNet, 0, len(sources))
	for _, s := range sources {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, net, err := net.ParseCIDR(s); err == nil {
			networks = append(networks, net)
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			var mask net.IPMask
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}
			networks = append(networks, &net.IPNet{IP: ip, Mask: mask})
			continue
		}
		log.Printf("⚠️ 忽略无效的过滤源: %s", s)
	}
	return &IPFilter{networks: networks}
}

// ❗ 修改: 实现白名单逻辑。
// 返回 true 表示**被过滤**（丢弃），返回 false 表示**不被过滤**（继续处理）。
func (f *IPFilter) IsFiltered(ip net.IP) bool {
	// 1. 如果白名单为空，则不过滤任何IP（允许所有，等同于禁用白名单）
	if ip == nil || len(f.networks) == 0 {
		return false 
	}
	
	// 2. 检查 IP 是否在白名单中
	for _, net := range f.networks {
		if net.Contains(ip) {
			return false // 匹配到白名单，不被过滤 (允许处理)
		}
	}
	
	// 3. 未匹配到白名单，被过滤 (丢弃)
	return true 
}

// ❗ 新增辅助函数: 获取所有本机非回环 IPv4 和 IPv6 地址
func getLocalIPs() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ips = append(ips, ip)
		}
	}
	return ips, nil
}


// ❗ 修改: MainControl 结构体现在包含 LogDispatcher 和 localIPs
type MainControl struct {
	config       Config
	configReload chan Config
	ipFilter     *IPFilter
	dispatcher   *LogDispatcher
	pcapHandles  map[string]*pcap.Handle 
	stopChan     chan struct{}
	localIPs     []net.IP // ❗ 新增: 缓存的本机 IP 列表
}

// NewMainControl ...
func NewMainControl(cfg Config) *MainControl {
    localIPs, err := getLocalIPs()
    if err != nil {
        log.Printf("⚠️ 无法获取本机 IP 列表: %v", err)
    }
    
	return &MainControl{
		config:       cfg,
		configReload: make(chan Config),
		ipFilter:     NewIPFilter(cfg.FilteredSources),
		dispatcher:   NewLogDispatcher(cfg),
		pcapHandles:  make(map[string]*pcap.Handle),
		stopChan:     make(chan struct{}),
        localIPs:     localIPs, // ❗ 初始化本机 IP 列表
	}
}

// Run 启动主控制循环
func (mc *MainControl) Run() {
	// 1. 启动配置监控
	watcher, err := NewConfigWatcher(configPath, mc.configReload)
	if err != nil {
		log.Fatalf("🚫 无法创建配置监控器: %v", err)
	}
	go watcher.Watch()

	// 2. 启动日志分发器
	mc.dispatcher.Start() // 启动 LogDispatcher 和其内部的发送器

	// 3. 启动流量捕获
	mc.startPcapCaptures()

	// 4. 监听系统信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("✅ 系统启动成功，等待信号或配置变化...")

	for {
		select {
		case newConfig := <-mc.configReload:
			// 接收到新配置
			if reflect.DeepEqual(mc.config.Listen, newConfig.Listen) && 
			   reflect.DeepEqual(mc.config.FilteredSources, newConfig.FilteredSources) && 
			   reflect.DeepEqual(mc.config.RemoteServers, newConfig.RemoteServers) {
				log.Println("🔔 配置已加载，但监听/过滤/远端服务器配置未变化，无需重启捕获/分发。")
				mc.config = newConfig
				// 仅更新 Dispatcher 和 IPFilter 的配置
				mc.updateComponents(newConfig)
				continue
			}

			// 配置有变化，需要重启捕获和分发
			log.Println("🔔 配置已变化，正在重启捕获和日志分发...")
			mc.shutdown()
			mc.config = newConfig
			mc.ipFilter = NewIPFilter(newConfig.FilteredSources)
			
            // ❗ 更新本机 IP 列表
            localIPs, err := getLocalIPs()
            if err != nil {
                log.Printf("⚠️ 重新加载时无法获取本机 IP 列表: %v", err)
            }
            mc.localIPs = localIPs

			// 重新初始化并启动 LogDispatcher
			mc.dispatcher = NewLogDispatcher(newConfig)
			mc.dispatcher.Start()
			
			// 重新启动捕获
			mc.pcapHandles = make(map[string]*pcap.Handle)
			mc.stopChan = make(chan struct{})
			mc.startPcapCaptures()

		case sig := <-sigChan:
			log.Printf("🛑 收到信号 %v，正在关闭系统...", sig)
			mc.shutdown()
			log.Println("✅ 系统已安全关闭。")
			return
		}
	}
}

func (mc *MainControl) updateComponents(newConfig Config) {
	// 简单的实现：重新创建 Dispatcher 以应用新配置（更健壮的实现应在 Dispatcher 内部处理配置热更新）
	mc.dispatcher.Stop()
	mc.dispatcher = NewLogDispatcher(newConfig)
	mc.dispatcher.Start()
	mc.ipFilter = NewIPFilter(newConfig.FilteredSources)
	mc.config = newConfig
    
    // ❗ 更新本机 IP 列表
    localIPs, err := getLocalIPs()
    if err != nil {
        log.Printf("⚠️ 更新组件时无法获取本机 IP 列表: %v", err)
    }
    mc.localIPs = localIPs
}

// shutdown 关闭所有捕获句柄和日志分发器
func (mc *MainControl) shutdown() {
	// 1. 关闭日志分发器
	mc.dispatcher.Stop()

	// 2. 停止所有 Pcap 捕获 Goroutine
	close(mc.stopChan)
	for key, handle := range mc.pcapHandles {
		handle.Close()
		log.Printf("✅ Pcap 句柄 %s 已关闭", key)
	}
}

// startPcapCaptures 启动所有配置的流量捕获 Goroutine
func (mc *MainControl) startPcapCaptures() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("🚫 无法查找设备: %v", err)
	}
	
	// ❗ 优化点 1: 创建配置的网卡名称/IP地址集合，方便快速查找
	targetInterfaces := make(map[string]bool)
	for _, iface := range mc.config.Interfaces {
		targetInterfaces[iface] = true
	}

	for _, d := range devices {
		
        // ❗ 优化点 2: 检查网卡是否在配置列表中 (增加灵活匹配)
        isTarget := false
        if len(mc.config.Interfaces) == 0 {
            // 如果配置列表为空，则监听所有网卡
            isTarget = true
        } else {
            // 1. 检查设备名是否精确匹配
            if targetInterfaces[d.Name] {
                isTarget = true
            }
            
            // 2. 检查设备别名或 IP 地址是否匹配配置中的名称
            if !isTarget {
                for _, ifaceName := range mc.config.Interfaces {
                    // 检查配置的名称是否包含在 pcap 设备的名称中（例如配置 eth0，pcap 找到 eth0 (some description)）
                    if strings.Contains(d.Name, ifaceName) {
                        isTarget = true
                        break
                    }
                }
            }

            // 3. 检查设备关联的 IP 地址是否与配置的名称匹配 (例如配置 ens18，但 pcap 找不到 ens18，我们必须依赖其他信息)
            if !isTarget {
                for _, _ = range d.Addresses {
                    // 检查 pcap 发现的 IP 地址是否是配置中期望的 IP/名称
                    // 考虑到用户配置的可能是 IP 地址，但也可能是接口名（如 ens18），
                    // 我们只需匹配 pcap 设备的实际名称 `d.Name` 或别名即可，
                    // 因为 pcap 库已经为我们找到了设备。
                    // 只需要确保我们不跳过 `ens18` 对应的 pcap 设备即可。
                    // 因为 d.Name 通常是 pcap 的内部名称，我们主要信任精确匹配和别名包含匹配。
                }
            }
        }
        
        if !isTarget {
            log.Printf("跳过未配置或不匹配的网卡: %s", d.Name)
            continue // 跳过未在 Interfaces 列表中指定的网卡
        }

        // 记录匹配到的设备，即使 d.Name 与配置文件中的名称不完全相同，只要匹配上就继续。
        log.Printf("✅ 匹配到网卡进行捕获: %s (配置名称: %v)", d.Name, mc.config.Interfaces)
        
        // 对于配置的网卡，遍历所有监听端口和协议
		for _, listenCfg := range mc.config.Listen {
			for _, proto := range listenCfg.Protocols {
				if strings.ToLower(proto) != "udp" && strings.ToLower(proto) != "tcp" {
					continue
				}
				
				// 构造 BPF 过滤表达式: 'udp port 514 or tcp port 514'
				filter := fmt.Sprintf("%s port %d", strings.ToLower(proto), listenCfg.Port)
				
				// 为每个配置的 (网卡, 协议, 端口) 组合启动一个 Goroutine 进行捕获
				go mc.captureDevice(d.Name, filter, listenCfg.Port, mc.dispatcher, mc.ipFilter)
			}
		}
	}
    
    // 检查是否有任何句柄启动成功。
    // 如果没有成功启动，很可能是 `pcap.OpenLive` 失败，而不是匹配失败。
    // 但是，如果你配置了网卡但没有一个 pcap.OpenLive 成功，仍然需要提醒用户。
    // 启动失败的日志会在 captureDevice 内部输出。
    
    // 保持原来的警告逻辑，但重点在于检查 `captureDevice` 内部的失败原因。
    // ... (保持原来的警告代码)
    if len(mc.config.Interfaces) > 0 && len(mc.pcapHandles) == 0 {
        // 此警告可能误报，因为 pcap.OpenLive 失败也会导致 pcapHandles 为空。
        // 最好是检查日志中是否有 '🚫 无法在设备 %s 上打开 Pcap' 的错误。
        // 为了简化，我们只在配置了网卡但一个都没启动时，打印详细信息。
        log.Printf("⚠️ 警告：配置了网卡但没有成功启动任何捕获句柄。这可能是由于网卡名称不匹配、权限不足或 BPF 过滤失败。请检查日志中的详细错误信息。配置的网卡名称: %v", mc.config.Interfaces)
    }
}

// captureDevice 负责在指定设备上进行数据包捕获
func (mc *MainControl) captureDevice(
	deviceName string, 
	filter string, 
	port int, 
	dispatcher *LogDispatcher, // ❗ 传入 LogDispatcher
	ipFilter *IPFilter,
) {
	// ... (打开 Pcap 句柄的逻辑保持不变)
	handle, err := pcap.OpenLive(deviceName, 65536, true, pcap.BlockForever)
	if err != nil {
		// 可能是权限问题或设备繁忙，只打印警告
		log.Printf("⚠️ 无法在设备 %s 上打开 Pcap (%s): %v", deviceName, filter, err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err != nil {
		log.Printf("🚫 设置 BPF 过滤器 %s 失败: %v", filter, err)
		return
	}
	
	key := fmt.Sprintf("%s_%s_%d", deviceName, strings.Split(filter, " ")[0], port)
	mc.pcapHandles[key] = handle
	log.Printf("✅ 已在设备 %s 上启动捕获，过滤器: %s", deviceName, filter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	for {
		select {
		case packet := <-packetSource.Packets():
			if packet != nil {
				// ❗ 修改：传入 LogDispatcher
				mc.processPacket(packet, dispatcher, ipFilter)
			}
			
		case <-mc.stopChan:
			log.Printf("🛑 Pcap 捕获 Goroutine (%s) 收到停止信号，即将关闭句柄...", key)
			return 
		}
	}
}

// ❗ 修改：processPacket 签名，接收 LogDispatcher，并检查本机 IP
func (mc *MainControl) processPacket(packet gopacket.Packet, dispatcher *LogDispatcher, ipFilter *IPFilter) {
	// ... (解析网络层和传输层的逻辑保持不变)
	var netLayer gopacket.NetworkLayer
	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		netLayer = layer.(*layers.IPv4)
	} else if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
		netLayer = layer.(*layers.IPv6)
	}

	var transportLayer gopacket.TransportLayer
	if layer := packet.Layer(layers.LayerTypeUDP); layer != nil {
		transportLayer = layer.(*layers.UDP)
	} else if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
		transportLayer = layer.(*layers.TCP)
	}

	appLayer := packet.ApplicationLayer()

	if netLayer != nil && transportLayer != nil && appLayer != nil {
		var srcIP net.IP
		switch v := netLayer.(type) {
		case *layers.IPv4:
			srcIP = v.SrcIP
		case *layers.IPv6:
			srcIP = v.SrcIP
		}

		if srcIP == nil || srcIP.IsLoopback() {
			return
		}

        // ❗ 新增：检查源 IP 是否为本机 IP (非回环)，显式丢弃
        for _, localIP := range mc.localIPs {
            // 确保比较的是相同类型的 IP (IPv4 vs IPv4 或 IPv6 vs IPv6)
            if srcIP.Equal(localIP) {
                // log.Printf("日志来自本机 IP，丢弃: %s", srcIP)
                return 
            }
        }
        
		// 检查白名单（FilteredSources 现在是白名单）
		// 如果 IsFiltered 返回 true，表示该 IP 不在白名单中，应该丢弃
		if ipFilter.IsFiltered(srcIP) {
			// log.Printf("日志来自不在白名单的 IP，丢弃: %s", srcIP)
			return
		}

		// 封装为 LogEntry
		entry := LogEntry{
			Timestamp: time.Now(),
			SourceIP:  srcIP.String(),
			Content:   appLayer.Payload(),
		}

		// ❗ 核心修改：将日志条目加入 LogDispatcher 队列
		dispatcher.Enqueue(entry)
	}
}

func main() {
	// 加载配置
	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("🚫 无法加载配置: %v", err)
	}

	// 启动主控制
	control := NewMainControl(cfg)
	control.Run()
}
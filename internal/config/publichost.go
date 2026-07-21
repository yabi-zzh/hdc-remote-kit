package config

import (
	"net"
	"strings"
)

// detectPublicHost 探测本机用于对外展示的 IPv4：优先默认出站地址（且可广告），
// 否则优先 RFC1918 私网地址，再回退其他可广告地址；仍失败则回退 127.0.0.1。
func detectPublicHost() string {
	candidates := listAdvertisableIPv4()
	outbound := outboundIPv4()
	if outbound != "" && isAdvertisableIPv4(net.ParseIP(outbound)) {
		if ip := net.ParseIP(outbound); ip != nil && ip.IsPrivate() {
			return outbound
		}
	}
	for _, ip := range candidates {
		if ip.IsPrivate() {
			return ip.String()
		}
	}
	if outbound != "" && isAdvertisableIPv4(net.ParseIP(outbound)) {
		return outbound
	}
	if len(candidates) > 0 {
		return candidates[0].String()
	}
	return "127.0.0.1"
}

// outboundIPv4 通过 UDP dial（不真正发包）解析本机默认出站网卡上的 IPv4。
func outboundIPv4() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil {
		return ""
	}
	ip := addr.IP.To4()
	if ip == nil {
		return ""
	}
	return ip.String()
}

func listAdvertisableIPv4() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var result []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
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
			if isAdvertisableIPv4(ip) {
				result = append(result, ip.To4())
			}
		}
	}
	return result
}

// isAdvertisableIPv4 过滤 loopback、链路本地、以及代理 Fake-IP 常用的 198.18.0.0/15。
func isAdvertisableIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil || ip4.IsLoopback() || !ip4.IsGlobalUnicast() {
		return false
	}
	// 198.18.0.0/15：基准测试/代理 Fake-IP 段，不适合作为 tconn 展示地址。
	if ip4[0] == 198 && ip4[1]&0xfe == 18 {
		return false
	}
	return true
}

// resolvePublicHost 环境变量非空则原样使用（去空白），否则自动探测。
func resolvePublicHost(envValue string) string {
	if host := strings.TrimSpace(envValue); host != "" {
		return host
	}
	return detectPublicHost()
}

package blocklist

import (
	"bufio"
	"log/slog"
	"net"
	"os"
	"strings"
)

// Blocklist represents a list of blocked IP addresses and CIDR blocks
type Blocklist struct {
	blocks []*net.IPNet
}

// New creates a new blocklist from a file
func New(filename string) (*Blocklist, error) {
	blocklist := &Blocklist{
		blocks: make([]*net.IPNet, 0),
	}

	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, err
	}

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read the file line by line
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments (lines starting with #)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse the line as IP/CIDR
		_, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			// Try parsing as a single IP
			ip := net.ParseIP(line)
			if ip == nil {
				slog.Warn("Invalid IP/CIDR in blocklist", "line", lineNum, "content", line)
				continue
			}

			// Convert single IP to CIDR
			if ip.To4() != nil {
				// IPv4
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else {
				// IPv6
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}

		blocklist.blocks = append(blocklist.blocks, ipnet)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	slog.Info("Loaded blocklist", "file", filename, "entries", len(blocklist.blocks))
	return blocklist, nil
}

// IsBlocked checks if an IP address is in the blocklist
func (b *Blocklist) IsBlocked(ip string) bool {
	// Extract IP from address (remove port if present)
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		// If SplitHostPort fails, assume it's already just an IP
		host = ip
	}

	// Parse the IP
	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		slog.Warn("Failed to parse IP", "ip", ip)
		return false
	}

	// Check if IP matches any blocked range
	for _, block := range b.blocks {
		if block.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// Reload reloads the blocklist from the file
func (b *Blocklist) Reload(filename string) error {
	newBlocklist, err := New(filename)
	if err != nil {
		return err
	}

	b.blocks = newBlocklist.blocks
	return nil
}

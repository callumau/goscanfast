package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var defaultPorts = []int{21, 22, 23, 25, 80, 135, 139, 161, 389, 443, 445, 636, 3389, 5985, 5986, 8080}

// LoadPorts parses a port specification from a file path, inline list, or
// returns the default port set when path is empty.
func LoadPorts(path string) ([]int, error) {
	if path == "" {
		return defaultPorts, nil
	}
	if looksLikePortList(path) {
		ports, err := parsePortList(path)
		if err != nil {
			return nil, err
		}
		return ports, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ports []int
	if err := json.Unmarshal(data, &ports); err != nil {
		return nil, fmt.Errorf("ports JSON must be an array of integers: %w", err)
	}
	if len(ports) == 0 {
		return nil, errors.New("ports JSON must not be empty")
	}
	return ports, nil
}

// LoadExcludeCIDRs reads a JSON array of CIDR strings to exclude from scanning.
func LoadExcludeCIDRs(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cidrs []string
	if err := json.Unmarshal(data, &cidrs); err != nil {
		return nil, fmt.Errorf("exclude JSON must be an array of CIDR strings: %w", err)
	}
	return cidrs, nil
}

// LoadTargetCIDRs reads scan targets from CLI args or a JSON file of CIDR strings.
func LoadTargetCIDRs(args []string, path string) ([]string, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var cidrs []string
		if err := json.Unmarshal(data, &cidrs); err != nil {
			return nil, fmt.Errorf("targets JSON must be an array of CIDR strings: %w", err)
		}
		if len(cidrs) == 0 {
			return nil, errors.New("targets JSON must not be empty")
		}
		return cidrs, nil
	}
	if len(args) == 0 {
		return nil, errors.New("requires at least one CIDR argument or --targets")
	}
	return args, nil
}

func looksLikePortList(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	for _, r := range trimmed {
		if (r >= '0' && r <= '9') || r == ',' || r == ' ' {
			continue
		}
		return false
	}
	return true
}

func parsePortList(value string) ([]int, error) {
	parts := strings.Split(value, ",")
	ports := make([]int, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		port, err := strconv.Atoi(trimmed)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port: %q", trimmed)
		}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		return nil, errors.New("ports list must not be empty")
	}
	return ports, nil
}

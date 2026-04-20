package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
)

type cidrBlock struct {
	base uint32
	mask uint32
}

func parseCIDRList(cidrs []string) ([]cidrBlock, error) {
	blocks := make([]cidrBlock, 0, len(cidrs))
	for _, raw := range cidrs {
		_, ipnet, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		ip := ipnet.IP.To4()
		if ip == nil {
			return nil, fmt.Errorf("CIDR %q is not IPv4", raw)
		}
		mask := net.IP(ipnet.Mask).To4()
		blocks = append(blocks, cidrBlock{base: ipToUint32(ip), mask: ipToUint32(mask)})
	}
	return blocks, nil
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func ipInCIDR(ip uint32, block cidrBlock) bool {
	return ip&block.mask == block.base&block.mask
}

func GenerateIPs(cidr string, excludes []string) (<-chan net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	baseIP := ipnet.IP.To4()
	if baseIP == nil {
		return nil, fmt.Errorf("CIDR %q is not IPv4", cidr)
	}
	mask := net.IP(ipnet.Mask).To4()
	if mask == nil {
		return nil, fmt.Errorf("CIDR %q is not IPv4", cidr)
	}

	excludeBlocks, err := parseCIDRList(excludes)
	if err != nil {
		return nil, err
	}

	start := ipToUint32(baseIP)
	maskInt := ipToUint32(mask)
	end := start | ^maskInt

	ch := make(chan net.IP, 1024)
	go func() {
		defer close(ch)
		for ip := start; ; ip++ {
			if len(excludeBlocks) > 0 {
				skipped := false
				for _, block := range excludeBlocks {
					if ipInCIDR(ip, block) {
						skipped = true
						break
					}
				}
				if skipped {
					if ip == end {
						break
					}
					continue
				}
			}
			ch <- uint32ToIP(ip)
			if ip == end {
				break
			}
		}
	}()
	return ch, nil
}

func GenerateIPsMulti(cidrs []string, excludes []string) (<-chan net.IP, error) {
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("no CIDRs provided")
	}

	// Normalize CIDRs to avoid duplicates and overlapping ranges
	normalized, err := normalizeCIDRs(cidrs)
	if err != nil {
		return nil, err
	}

	excludeBlocks, err := parseCIDRList(excludes)
	if err != nil {
		return nil, err
	}
	ch := make(chan net.IP, 1024)
	go func() {
		defer close(ch)
		var wg sync.WaitGroup
		for _, cidr := range normalized {
			baseIP := cidr.IP.To4()
			mask := net.IP(cidr.Mask).To4()
			start := ipToUint32(baseIP)
			maskInt := ipToUint32(mask)
			end := start | ^maskInt

			wg.Add(1)
			go func(s, e uint32) {
				defer wg.Done()
				for ip := s; ; ip++ {
					skipped := false
					for _, block := range excludeBlocks {
						if ipInCIDR(ip, block) {
							skipped = true
							break
						}
					}
					if !skipped {
						ch <- uint32ToIP(ip)
					}
					if ip == e {
						break
					}
				}
			}(start, end)
		}
		wg.Wait()
	}()
	return ch, nil
}

func normalizeCIDRs(cidrs []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		nets = append(nets, ipnet)
	}

	// Sort by network address, then by mask length (shorter mask / larger network first)
	sort.Slice(nets, func(i, j int) bool {
		ipI := ipToUint32(nets[i].IP.To4())
		ipJ := ipToUint32(nets[j].IP.To4())
		if ipI != ipJ {
			return ipI < ipJ
		}
		maskI, _ := nets[i].Mask.Size()
		maskJ, _ := nets[j].Mask.Size()
		return maskI < maskJ
	})

	merged := make([]*net.IPNet, 0, len(nets))
	for _, n := range nets {
		keep := true
		for _, m := range merged {
			if m.Contains(n.IP) {
				// n is already covered by m because m is larger or equal and comes first/same start
				keep = false
				break
			}
		}
		if keep {
			merged = append(merged, n)
		}
	}
	return merged, nil
}

func CIDRSize(cidr string) uint64 {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}
	baseIP := ipnet.IP.To4()
	if baseIP == nil {
		return 0
	}
	mask := net.IP(ipnet.Mask).To4()
	if mask == nil {
		return 0
	}
	start := ipToUint32(baseIP)
	maskInt := ipToUint32(mask)
	end := start | ^maskInt
	if end < start {
		return 0
	}
	return uint64(end-start) + 1
}

func TotalCIDRSize(cidrs []string) uint64 {
	normalized, err := normalizeCIDRs(cidrs)
	if err != nil {
		return 0
	}
	var total uint64
	for _, cidr := range normalized {
		baseIP := cidr.IP.To4()
		mask := net.IP(cidr.Mask).To4()
		start := ipToUint32(baseIP)
		maskInt := ipToUint32(mask)
		end := start | ^maskInt
		total += uint64(end-start) + 1
	}
	return total
}

func CIDRRange(cidr string) (string, string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}
	baseIP := ipnet.IP.To4()
	if baseIP == nil {
		return "", "", fmt.Errorf("CIDR %q is not IPv4", cidr)
	}
	mask := net.IP(ipnet.Mask).To4()
	if mask == nil {
		return "", "", fmt.Errorf("CIDR %q is not IPv4", cidr)
	}
	start := ipToUint32(baseIP)
	maskInt := ipToUint32(mask)
	end := start | ^maskInt
	return uint32ToIP(start).String(), uint32ToIP(end).String(), nil
}

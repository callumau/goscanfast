package scanner

import (
	"fmt"
	"net"
	"sort"
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
		blocks = append(blocks, cidrBlock{base: IpToUint32(ip), mask: IpToUint32(mask)})
	}
	return blocks, nil
}

// IpToUint32 converts net.IP to uint32.
func IpToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func ipInCIDR(ip uint32, block cidrBlock) bool {
	return ip&block.mask == block.base&block.mask
}

// GenerateIPs returns a channel that yields every IPv4 address in cidr,
// skipping any address that falls within an exclude range.
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

	start := IpToUint32(baseIP)
	maskInt := IpToUint32(mask)
	end := start | ^maskInt

	ch := make(chan net.IP, 1024)
	go func() {
		defer close(ch)
		for ip := start; ; {
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
					ip++
					continue
				}
			}
			ch <- uint32ToIP(ip)
			if ip == end {
				break
			}
			ip++
		}
	}()
	return ch, nil
}

// GenerateIPsMulti returns a channel yielding every IPv4 address across
// multiple CIDRs, deduplicating overlapping ranges and skipping excludes.
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
		for _, cidr := range normalized {
			baseIP := cidr.IP.To4()
			mask := net.IP(cidr.Mask).To4()
			start := IpToUint32(baseIP)
			maskInt := IpToUint32(mask)
			end := start | ^maskInt

			for ip := start; ; {
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
				if ip == end {
					break
				}
				ip++
			}
		}
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
		ipI := IpToUint32(nets[i].IP.To4())
		ipJ := IpToUint32(nets[j].IP.To4())
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

// CIDRSize returns the number of IPv4 addresses in the given CIDR.
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
	start := IpToUint32(baseIP)
	maskInt := IpToUint32(mask)
	end := start | ^maskInt
	if end < start {
		return 0
	}
	return uint64(end-start) + 1
}

// TotalCIDRSize returns the total number of IPv4 addresses across cidrs,
// accounting for overlapping ranges.
func TotalCIDRSize(cidrs []string) uint64 {
	normalized, err := normalizeCIDRs(cidrs)
	if err != nil {
		return 0
	}
	var total uint64
	for _, cidr := range normalized {
		baseIP := cidr.IP.To4()
		mask := net.IP(cidr.Mask).To4()
		start := IpToUint32(baseIP)
		maskInt := IpToUint32(mask)
		end := start | ^maskInt
		total += uint64(end-start) + 1
	}
	return total
}

// TotalScannableHosts returns the number of IPs across cidrs that remain
// after subtracting any address covered by excludes. Returns 0 on any
// parse error (callers surface the error via GenerateIPsMulti).
func TotalScannableHosts(cidrs, excludes []string) uint64 {
	normalized, err := normalizeCIDRs(cidrs)
	if err != nil {
		return 0
	}
	excludeBlocks, err := parseCIDRList(excludes)
	if err != nil {
		return 0
	}

	// Build merged exclude intervals in uint64 space so 255.255.255.255+1
	// cannot overflow.
	intervals := make([][2]uint64, 0, len(excludeBlocks))
	for _, b := range excludeBlocks {
		intervals = append(intervals, [2]uint64{
			uint64(b.base & b.mask),
			uint64(b.base | ^b.mask),
		})
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i][0] < intervals[j][0] })
	merged := make([][2]uint64, 0, len(intervals))
	for _, iv := range intervals {
		if n := len(merged); n > 0 && iv[0] <= merged[n-1][1]+1 {
			if iv[1] > merged[n-1][1] {
				merged[n-1][1] = iv[1]
			}
			continue
		}
		merged = append(merged, iv)
	}

	var total uint64
	for _, cidr := range normalized {
		baseIP := cidr.IP.To4()
		mask := net.IP(cidr.Mask).To4()
		lo := uint64(IpToUint32(baseIP))
		hi := uint64(IpToUint32(baseIP) | ^IpToUint32(mask))
		size := hi - lo + 1
		for _, ex := range merged {
			if ex[1] < lo {
				continue
			}
			if ex[0] > hi {
				break
			}
			ovLo := max(lo, ex[0])
			ovHi := min(hi, ex[1])
			size -= ovHi - ovLo + 1
		}
		total += size
	}
	return total
}

// CIDRRange returns the first and last IP addresses in a CIDR block.
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
	start := IpToUint32(baseIP)
	maskInt := IpToUint32(mask)
	end := start | ^maskInt
	return uint32ToIP(start).String(), uint32ToIP(end).String(), nil
}
